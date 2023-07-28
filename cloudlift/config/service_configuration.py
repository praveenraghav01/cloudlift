'''
This module abstracts implementation of storing, editing and
retrieving service configuration.
'''

import json
from time import sleep

import random
import dictdiffer
from botocore.exceptions import ClientError
from click import confirm, edit
from cloudlift.exceptions import UnrecoverableException
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from stringcase import pascalcase

from cloudlift.config import DecimalEncoder
# import config.mfa as mfa
from cloudlift.config import  get_client_for, print_json_changes, get_resource_for
from cloudlift.config.logging import log_bold, log_err, log_warning, log
from cloudlift.version import VERSION
from cloudlift.config.dynamodb_configuration import DynamodbConfiguration
from cloudlift.config.pre_flight import check_sns_topic_exists


SERVICE_CONFIGURATION_TABLE = 'service_configurations'
DEFAULT_TARGET_GROUP_DEREGISTRATION_DELAY = 30
DEFAULT_LOAD_BALANCING_ALGORITHM = u'least_outstanding_requests'
DEFAULT_HEALTH_CHECK_HEALTHY_THRESHOLD_COUNT = 2
DEFAULT_HEALTH_CHECK_UNHEALTHY_THRESHOLD_COUNT = 3
DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS = 30
DEFAULT_HEALTH_CHECK_TIMEOUT_SECONDS = 10


class ServiceConfiguration(object):
    '''
        Handles configuration in DynamoDB for services
    '''

    def __init__(self, service_name, environment):
        self.service_name = service_name
        self.environment = environment
        self.new_service = False
        # TODO: Use the below two lines when all parameter store actions
        # require MFA
        #
        # mfa_region = get_region_for_environment(environment)
        # mfa_session = mfa.get_mfa_session(mfa_region)
        # ssm_client = mfa_session.client('ssm')
        self.dynamodb_resource = get_resource_for('dynamodb',environment)
        self.table = DynamodbConfiguration(SERVICE_CONFIGURATION_TABLE, [
            ('service_name', self.service_name), ('environment', self.environment)])._get_table()

    def edit_config(self, no_editor=False):
        '''
            Open editor to update configuration
        '''

        try:
            from cloudlift.version import VERSION
            current_configuration = self.get_config(VERSION)

            if no_editor:
                self.set_config(current_configuration)
                log_warning("Using configuration from dynamoDB.")
            
            else:
                updated_configuration = edit(
                    json.dumps(
                        current_configuration,
                        indent=4,
                        sort_keys=True,
                        cls=DecimalEncoder
                    )
                )

                if updated_configuration is None:
                    if self.new_service:
                        self.set_config(current_configuration)
                        log_warning("Using default configuration.")
                    else:
                        log_warning("No changes made.")
                else:
                    updated_configuration = json.loads(updated_configuration)
                    differences = list(dictdiffer.diff(
                        current_configuration,
                        updated_configuration
                    ))
                    if not differences:
                        log_warning("No changes made.")
                    else:
                        print_json_changes(differences)
                        if confirm('Do you want update the config?'):
                            self.set_config(updated_configuration)
                        else:
                            log_warning("Changes aborted.")
        except ClientError:
            raise UnrecoverableException("Unable to fetch service configuration from DynamoDB.")

    def get_config(self, cloudlift_version):
        '''
            Get configuration from DynamoDB
        '''

        try:
            configuration_response = self.table.get_item(
                Key={
                    'service_name': self.service_name,
                    'environment': self.environment
                },
                ConsistentRead=True,
                AttributesToGet=[
                    'configuration'
                ]
            )
            if 'Item' in configuration_response:
                existing_configuration = configuration_response['Item']['configuration']

                from distutils.version import LooseVersion
                previous_cloudlift_version = existing_configuration.pop("cloudlift_version", None)
                if LooseVersion(cloudlift_version) < LooseVersion(previous_cloudlift_version):
                    raise UnrecoverableException(f'Cloudlift Version {previous_cloudlift_version} was used to '
                                                 f'create this service. You are using version {cloudlift_version}, '
                                                 f'which is older and can cause corruption. Please upgrade to at least '
                                                 f'version {previous_cloudlift_version} to proceed.\n\nUpgrade to the '
                                                 f'latest version (Recommended):\n'
                                                 f'\tpip install -U cloudlift\n\nOR\n\nUpgrade to a compatible version:\n'
                                                 f'\tpip install -U cloudlift=={previous_cloudlift_version}')
            else:
                existing_configuration = self._default_service_configuration()
                self.new_service = True

            return existing_configuration
        except ClientError:
            raise UnrecoverableException("Unable to fetch service configuration from DynamoDB.")

    def set_config(self, config, information_fetcher=None):
        '''
            Set configuration in DynamoDB
        '''
        config['cloudlift_version'] = VERSION
        for service_name, service_config in config['services'].items():
            if 'http_interface' not in service_config:
                continue
            reuse_existing_alb = 'alb' in service_config['http_interface'] and (service_config['http_interface']['alb'].get('create_new', False) is False)
            if reuse_existing_alb and 'priority' not in service_config['http_interface']['alb']:
                listener_arn = service_config['http_interface']['alb']['listener_arn']
                service_config['http_interface']['alb']['priority'] = self._get_listener_rule_priority_for_service(listener_arn, service_name, information_fetcher)
        self._validate_changes(config)
        check_sns_topic_exists(config['notifications_arn'], self.environment)
        try:
            configuration_response = self.table.update_item(
                TableName=SERVICE_CONFIGURATION_TABLE,
                Key={
                    'service_name': self.service_name,
                    'environment': self.environment
                },
                UpdateExpression='SET configuration = :configuration',
                ExpressionAttributeValues={
                    ':configuration': config
                },
                ReturnValues="UPDATED_NEW"
            )
            return configuration_response
        except ClientError:
            raise UnrecoverableException("Unable to store service configuration in DynamoDB.")

    def _get_listener_rule_priority_for_service(self, listener_arn, service_name, information_fetcher):
        elb_client = get_client_for('elbv2', self.environment)
        response = elb_client.describe_rules(
            ListenerArn=listener_arn,
        )
        listener_rules = list(response.get('Rules', []))

        while 'NextMarker' in response:
            response = elb_client.describe_rules(
                ListenerArn=listener_arn,
                Marker=response['NextMarker'],
            )
            listener_rules.extend(response.get('Rules', []))

        if information_fetcher:
            service_listener_rule = information_fetcher.get_existing_listener_rule_summary(service_name)
            if service_listener_rule:
                matching_priority = next((rule['Priority'] for rule in listener_rules if
                                          rule['RuleArn'] == service_listener_rule['PhysicalResourceId']), None)
                if matching_priority:
                    return int(matching_priority)

        return self._get_random_available_listener_rule_priority(listener_rules, listener_arn)

    @staticmethod
    def _get_random_available_listener_rule_priority(listener_rules, listener_arn):
        occupied_priorities = set(rule['Priority'] for rule in listener_rules)
        available_priorities = set(range(1, 50001)) - occupied_priorities
        if not available_priorities:
            raise UnrecoverableException("No listener rule priorities available for listener_arn: {}".format(listener_arn))
        return int(random.choice(list(available_priorities)))

    def update_cloudlift_version(self):
        '''
            Updates cloudlift version in service configuration
        '''
        config = self.get_config(VERSION)
        self.set_config(config)

    def _validate_changes(self, configuration):
        service_schema = {
            "title": "service",
            "type": "object",
            "properties": {
                "http_interface": {
                    "type": "object",
                    "properties": {
                        "internal": {
                            "type": "boolean"
                        },
                        "alb": {
                            "type": "object",
                            "properties": {
                                "create_new": {
                                    "type": "boolean",
                                },
                                "listener_arn": {
                                    "type": "string"
                                },
                                "target_5xx_error_threshold": {
                                    "type": "number"
                                },
                                "host": {
                                    "type": "string"
                                },
                                "path": {
                                    "type": "string"
                                },
                                "priority": {
                                    "type": "number"
                                }
                            },
                            "required": [
                                "create_new"
                            ]
                        },
                        "restrict_access_to": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "container_port": {
                            "type": "number"
                        },
                        "health_check_path": {
                            "type": "string",
                            "pattern": "^\/.*$"
                        },
                        "health_check_healthy_threshold_count": {
                            "type": "number",
                            "minimum": 2,
                            "maximum": 10
                        },
                        "health_check_unhealthy_threshold_count": {
                            "type": "number",
                            "minimum": 2,
                            "maxium": 10
                        },
                        "health_check_interval_seconds": {
                            "type": "number",
                            "minimum": 5,
                            "maximum": 300
                        },
                        "health_check_timeout_seconds": {
                            "type": "number",
                            "minimum": 2,
                            "maximum": 120
                        },
                        "load_balancing_algorithm": {
                            "type": "string",
                            "enum": ["round_robin", "least_outstanding_requests"]
                        },
                        "deregistration_delay": {
                            "type": "number"
                        }
                    },
                    "required": [
                        "internal",
                        "restrict_access_to",
                        "container_port"
                    ]
                },
                "custom_metrics": {
                    "type": "object",
                    "properties": {
                        "metrics_port" : {"type": "string"},
                        "metrics_path": {"type": "string"}
                    }
                },
                "volume": {
                    "type": "object",
                    "properties": {
                        "efs_id" : {"type": "string"},
                        "efs_directory_path" : {"type": "string"},
                        "container_path" : {"type": "string"}
                    }
                },
                "memory_reservation": {
                    "type": "number",
                    "minimum": 10,
                    "maximum": 30000
                },
                "fargate": {
                    "type": "object",
                    "properties": {
                        "cpu": {
                            "type": "number",
                            "minimum": 256,
                            "maximum": 4096
                        },
                        "memory": {
                            "type": "number",
                            "minimum": 512,
                            "maximum": 30720
                        }
                    }
                },
                "command": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "null"}
                    ]
                },
                "spot_deployment": {
                    "type": "boolean"
                },
                "logging": {
                    "oneOf": [
                        {"type": "string", "pattern": "^(awslogs|fluentd|null)$"},
                        {"type": "null"}
                    ]
                },
                "autoscaling": {
                    "type": "object",
                    "properties": {
                        "max_capacity": {
                            "type": "number"
                        },
                        "min_capacity": {
                            "type": "number"
                        },
                        "request_count_per_target": {
                            "type": "object",
                            "properties": {
                                "alb_arn": {
                                    "type": "string"
                                },
                                "target_value": {
                                    "type": "number"
                                },
                                "scale_in_cool_down_seconds": {
                                    "type": "number"
                                },
                                "scale_out_cool_down_seconds": {
                                    "type": "number"
                                }
                            },
                            "required": ['target_value', 'scale_in_cool_down_seconds', 'scale_out_cool_down_seconds']
                        },
                    },
                    "required": ['max_capacity', 'min_capacity']
                }
            },
            "required": ["memory_reservation", "command"]
        }
        schema = {
            # "$schema": "http://json-schema.org/draft-04/schema#",
            "title": "configuration",
            "type": "object",
            "properties": {
                "notifications_arn": {
                    "type": "string"
                },
                "services": {
                    "type": "object",
                    "patternProperties": {
                        "^[a-zA-Z]+$": service_schema
                    }
                },
                "cloudlift_version": {
                    "type": "string"
                }
            },
            "required": ["cloudlift_version", "services", "notifications_arn"]
        }
        try:
            validate(configuration, schema)
        except ValidationError as validation_error:
            if validation_error.relative_path:
                raise UnrecoverableException(validation_error.message + " in " +
                        str(".".join(list(validation_error.relative_path))))
            else:
                raise UnrecoverableException(validation_error.message)
        log_bold("Schema valid!")

    def _default_service_configuration(self):
        return {
            u'notifications_arn': None,
            u'services': {
                pascalcase(self.service_name): {
                    u'http_interface': {
                        u'internal': False,
                        u'alb': {
                            u'create_new': True,
                        },
                        u'restrict_access_to': [u'0.0.0.0/0'],
                        u'container_port': 80,
                        u'health_check_path': u'/elb-check',
                        u'load_balancing_algorithm': DEFAULT_LOAD_BALANCING_ALGORITHM,
                        u'deregistration_delay': DEFAULT_TARGET_GROUP_DEREGISTRATION_DELAY
                    },
                    u'memory_reservation': 250,
                    u'command': None,
                    u'spot_deployment': False
                }
            }
        }
