import json
import re
import uuid

import boto3
from botocore.exceptions import ClientError
from cloudlift.exceptions import UnrecoverableException
from cloudlift.config import get_client_for

from awacs.aws import PolicyDocument, Statement, Allow, Principal
from awacs.sts import AssumeRole
from cfn_flip import to_yaml
from stringcase import pascalcase
from troposphere import GetAtt, Output, Parameter, Ref, Sub, ImportValue, Tags, Select, Split
from troposphere.cloudwatch import Alarm, MetricDimension
from troposphere.applicationautoscaling import ScalableTarget, ScheduledAction, ScalableTargetAction
from troposphere.applicationautoscaling import ScalingPolicy, TargetTrackingScalingPolicyConfiguration, \
    PredefinedMetricSpecification
from troposphere.ec2 import SecurityGroup
from troposphere.ecs import (AwsvpcConfiguration, ContainerDefinition,
                             DeploymentConfiguration, Secret, MountPoint,
                             LoadBalancer, LogConfiguration, Volume, EFSVolumeConfiguration,
                             NetworkConfiguration, PlacementStrategy,
                             PortMapping, Service, TaskDefinition, ServiceRegistry, PlacementConstraint)
from troposphere.elasticloadbalancingv2 import (Action, Certificate, Listener, ListenerRule, ListenerRuleAction,
                                                Condition, HostHeaderConfig, PathPatternConfig)
from troposphere.elasticloadbalancingv2 import LoadBalancer as ALBLoadBalancer
from troposphere.elasticloadbalancingv2 import (Matcher, RedirectConfig,
                                                TargetGroup,
                                                TargetGroupAttribute)
from troposphere.iam import Role
from troposphere.servicediscovery import Service as SD
from troposphere.servicediscovery import DnsConfig, DnsRecord
from troposphere.events import Rule, Target

from cloudlift.config.service_configuration import DEFAULT_TARGET_GROUP_DEREGISTRATION_DELAY, \
    DEFAULT_LOAD_BALANCING_ALGORITHM, DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS, DEFAULT_HEALTH_CHECK_TIMEOUT_SECONDS, \
    DEFAULT_HEALTH_CHECK_HEALTHY_THRESHOLD_COUNT, DEFAULT_HEALTH_CHECK_UNHEALTHY_THRESHOLD_COUNT
from cloudlift.config import region as region_service
from cloudlift.config import get_account_id
from cloudlift.config import DecimalEncoder, VERSION
from cloudlift.config import get_service_stack_name
from cloudlift.deployment.deployer import build_config
from cloudlift.deployment.ecs import DeployAction, EcsClient
from cloudlift.config.logging import log, log_bold
from cloudlift.deployment.service_information_fetcher import ServiceInformationFetcher
from cloudlift.deployment.template_generator import TemplateGenerator


class ServiceTemplateGenerator(TemplateGenerator):
    PLACEMENT_STRATEGIES = [
        PlacementStrategy(
            Type='spread',
            Field='attribute:ecs.availability-zone'
        ),
        PlacementStrategy(
            Type='spread',
            Field='instanceId'
        )]
    LAUNCH_TYPE_FARGATE = 'FARGATE'
    LAUNCH_TYPE_EC2 = 'EC2'

    def __init__(self, service_configuration, environment_stack, bucket_name=None, env_sample_file_path=None):
        super(ServiceTemplateGenerator, self).__init__(
            service_configuration.environment
        )
        self._derive_configuration(service_configuration)
        self.env_sample_file_path = env_sample_file_path
        self.environment_stack = environment_stack
        self.current_version = ServiceInformationFetcher(
            self.application_name, self.env).get_current_version()
        self.bucket_name = bucket_name
        self.environment = service_configuration.environment
        self.client = get_client_for('s3', self.environment)
        self.team_name = (self.notifications_arn.split(':')[-1])

    def _derive_configuration(self, service_configuration):
        self.application_name = service_configuration.service_name
        self.configuration = service_configuration.get_config(VERSION)

    def generate_service(self):
        self._add_service_parameters()
        self._add_service_outputs()
        self._fetch_current_desired_count()
        self._add_ecs_service_iam_role()
        self._add_cluster_services()

        key = uuid.uuid4().hex + '.yml'
        if len(to_yaml(self.template.to_json())) > 51000:
            try:
                self.client.put_object(
                    Body=to_yaml(self.template.to_json()),
                    Bucket=self.bucket_name,
                    Key=key,
                )
                template_url = f'https://{self.bucket_name}.s3.amazonaws.com/{key}'
                return template_url, 'TemplateURL', key
            except ClientError as boto_client_error:
                error_code = boto_client_error.response['Error']['Code']
                if error_code == 'AccessDenied':
                    raise UnrecoverableException(f'Unable to store cloudlift service template in S3 bucket at {self.bucket_name}')
                else:
                    raise boto_client_error
        else:
            return to_yaml(self.template.to_json()), 'TemplateBody', ''

    def _add_cluster_services(self):
        for ecs_service_name, config in self.configuration['services'].items():
            self._add_service(ecs_service_name, config)

    def _add_service_alarms(self, svc):
        oom_event_rule = Rule(
            'EcsOOM' + str(svc.name),
            Description="Triggered when an Amazon ECS Task is stopped",
            EventPattern={
                "detail-type": ["ECS Task State Change"],
                "source": ["aws.ecs"],
                "detail": {
                    "clusterArn": [{"anything-but": [str(self.cluster_name)]}],
                    "containers": {
                        "reason": [{
                            "prefix": "OutOfMemory"
                        }]
                    },
                    "desiredStatus": ["STOPPED"],
                    "lastStatus": ["STOPPED"],
                    "taskDefinitionArn": [{
                        "anything-but": [str(svc.name) + "Family"]
                    }]
                }
            },
            State="ENABLED",
            Targets=[Target(
                    Arn=Ref(self.notification_sns_arn),
                    Id="ECSOOMStoppedTasks",
                    InputPath="$.detail.containers[0]"
                )
            ]
        )
        self.template.add_resource(oom_event_rule)

        ecs_high_cpu_alarm = Alarm(
            'EcsHighCPUAlarm' + str(svc.name),
            EvaluationPeriods=1,
            Dimensions=[
                MetricDimension(
                    Name='ClusterName',
                    Value=self.cluster_name
                ),
                MetricDimension(
                    Name='ServiceName',
                    Value=GetAtt(svc, 'Name')
                )],
            AlarmActions=[Ref(self.notification_sns_arn)],
            OKActions=[Ref(self.notification_sns_arn)],
            AlarmDescription='Alarm if CPU too high or metric disappears \
indicating instance is down',
            Namespace='AWS/ECS',
            Period=300,
            ComparisonOperator='GreaterThanThreshold',
            Statistic='Average',
            Threshold='80',
            MetricName='CPUUtilization'
        )
        self.template.add_resource(ecs_high_cpu_alarm)
        ecs_high_memory_alarm = Alarm(
            'EcsHighMemoryAlarm' + str(svc.name),
            EvaluationPeriods=1,
            Dimensions=[
                MetricDimension(
                    Name='ClusterName',
                    Value=self.cluster_name
                ),
                MetricDimension(
                    Name='ServiceName',
                    Value=GetAtt(svc, 'Name')
                )
            ],
            AlarmActions=[Ref(self.notification_sns_arn)],
            OKActions=[Ref(self.notification_sns_arn)],
            AlarmDescription='Alarm if memory too high or metric \
disappears indicating instance is down',
            Namespace='AWS/ECS',
            Period=300,
            ComparisonOperator='GreaterThanThreshold',
            Statistic='Average',
            Threshold='120',
            MetricName='MemoryUtilization'
        )
        self.template.add_resource(ecs_high_memory_alarm)
        # How to add service task count alarm
        # http://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-metrics.html#cw_running_task_count
#         ecs_no_running_tasks_alarm = Alarm(
#             'EcsNoRunningTasksAlarm' + str(svc.name),
#             EvaluationPeriods=1,
#             Dimensions=[
#                 MetricDimension(
#                     Name='ClusterName',
#                     Value=self.cluster_name
#                 ),
#                 MetricDimension(
#                     Name='ServiceName',
#                     Value=GetAtt(svc, 'Name')
#                 )
#             ],
#             AlarmActions=[Ref(self.notification_sns_arn)],
#             OKActions=[Ref(self.notification_sns_arn)],
#             AlarmDescription='Alarm if the task count goes to zero, denoting \
# service is down',
#             Namespace='AWS/ECS',
#             Period=60,
#             ComparisonOperator='LessThanThreshold',
#             Statistic='SampleCount',
#             Threshold='1',
#             MetricName='CPUUtilization',
#             TreatMissingData='breaching'
#         )
#         self.template.add_resource(ecs_no_running_tasks_alarm)

    def _add_scalable_target(self, ecs_svc, config, scheduled_actions):
        resource_id = Sub('service/' + self.cluster_name + '/' + '${service_name}',
                          service_name=GetAtt(ecs_svc, "Name"))
        scalable_target = ScalableTarget(
            str(ecs_svc.name) + "ScalableTarget",
            MinCapacity=int(config.get('min_capacity')),
            MaxCapacity=int(config.get('max_capacity')),
            ResourceId=resource_id,
            RoleARN=f'arn:aws:iam::{self.account_id}:role/aws-service-role/ecs.application-autoscaling.amazonaws.com/AWSServiceRoleForApplicationAutoScaling_ECSService',
            ScalableDimension='ecs:service:DesiredCount',
            ServiceNamespace='ecs',
            ScheduledActions=scheduled_actions
        )
        self.template.add_resource(scalable_target)
        return scalable_target

    def _build_scheduled_action(self, ecs_svc, config):
        schedules_actions = []
        for key, value in config.items():
            scalable_target_action = ScalableTargetAction(
                str(ecs_svc.name) + "STA" + pascalcase(key),
                MaxCapacity=int(value.get('max_capacity')),
                MinCapacity=int(value.get('min_capacity'))
            )
            action = ScheduledAction(
                str(ecs_svc.name) + "SA" + pascalcase(key),
                ScalableTargetAction=scalable_target_action,
                Schedule=value.get('schedule'),
                ScheduledActionName=pascalcase(str(ecs_svc.name)) + pascalcase(self.env) + pascalcase(key),
                Timezone=value.get('timezone'),
            )
            schedules_actions.append(action)
        return schedules_actions

    # def _add_scalable_target_alarms(self, service_name, ecs_svc, config):
    #     max_scalable_target_alarm = Alarm(
    #         'MaxScalableTargetAlarm' + service_name,
    #         EvaluationPeriods=3,
    #         DatapointsToAlarm=3,
    #         Dimensions=[
    #             MetricDimension(
    #                 Name='ServiceName',
    #                 Value=GetAtt(ecs_svc, 'Name')
    #             ),
    #             MetricDimension(
    #                 Name='ClusterName',
    #                 Value=self.cluster_name
    #             )
    #         ],
    #         AlarmActions=[Ref(self.notification_sns_arn)],
    #         OKActions=[Ref(self.notification_sns_arn)],
    #         AlarmDescription='Triggers if desired task count of a service is equal to max_capacity,' +
    #                          ' review auto scaling configuration if this alarm triggers',
    #         Namespace='ECS/ContainerInsights',
    #         Period=300,
    #         ComparisonOperator='GreaterThanOrEqualToThreshold',
    #         Statistic='Maximum',
    #         Threshold=int(config.get('max_capacity')),
    #         MetricName='DesiredTaskCount',
    #         TreatMissingData='notBreaching'
    #     )
    #     self.template.add_resource(max_scalable_target_alarm)

    def _add_alb_request_count_scaling_policy(self, ecs_svc, alb_arn, target_group, config, scalable_target):
        try:
            target_value = int(config.get('target_value'))
            scale_in_cool_down = int(config.get('scale_in_cool_down_seconds'))
            scale_out_cool_down = int(config.get('scale_out_cool_down_seconds'))
        except TypeError as e:
            raise UnrecoverableException('The following value has to be integer: {}'.format(e))

        if type(alb_arn) == str:
            alb_name = alb_arn.split('/')[2]
            alb_id = alb_arn.split('/')[3]
        else:
            alb_name = Select(2, Split('/', Ref(alb_arn)))
            alb_id = Select(3, Split('/', Ref(alb_arn)))

        tg_name = Select(1, Split('/', Ref(target_group)))
        tg_id = Select(2, Split('/', Ref(target_group)))
        self.template.add_resource(
            ScalingPolicy(
                str(ecs_svc.name) + 'ALBRequestCountPerTargetScalingPolicy',
                PolicyName='requestCountPerTarget',
                PolicyType='TargetTrackingScaling',
                TargetTrackingScalingPolicyConfiguration=TargetTrackingScalingPolicyConfiguration(
                    ScaleInCooldown=scale_in_cool_down,
                    ScaleOutCooldown=scale_out_cool_down,
                    TargetValue=target_value,
                    PredefinedMetricSpecification=PredefinedMetricSpecification(
                        PredefinedMetricType='ALBRequestCountPerTarget',
                        ResourceLabel=Sub("app/${alb_name}/${alb_id}/targetgroup/${tg_name}/${tg_id}", alb_id=alb_id,
                                          alb_name=alb_name, tg_name=tg_name, tg_id=tg_id)
                    )
                ),
                ScalingTargetId=Ref(scalable_target)
            )
        )

    def _add_service(self, service_name, config):
        launch_type = self.LAUNCH_TYPE_FARGATE if 'fargate' in config else self.LAUNCH_TYPE_EC2
        env_config = build_config(
            self.env,
            self.application_name,
            self.env_sample_file_path
        )
        container_definition_arguments = {
            "Secrets": [
                Secret(Name=k, ValueFrom=v) for (k, v) in env_config
            ],
            "Name": service_name + "Container",
            "Image": self.ecr_image_uri + ':' + self.current_version,
            "Essential": 'true',
            "Cpu": 0
        }
        
        autoscaling_config = config['autoscaling'] if 'autoscaling' in config else {}
        desired_count = self._get_desired_task_count_for_service(service_name,
                                                                 min_count=int(autoscaling_config.get('min_capacity', 0)))
        placement_constraint = {}
        for key in self.environment_stack["Outputs"]:
            if key["OutputKey"] == 'ECSClusterDefaultInstanceLifecycle':
                spot_deployment = False if ImportValue("{self.env}ECSClusterDefaultInstanceLifecycle".format(**locals())) == 'ondemand' else True
                placement_constraint = {
                    "PlacementConstraints": [PlacementConstraint(
                        Type='memberOf',
                        Expression='attribute:deployment_type == spot' if spot_deployment else 'attribute:deployment_type == ondemand'
                    )],
                }
        if 'spot_deployment' in config:
            spot_deployment = config["spot_deployment"]
            placement_constraint = {
                "PlacementConstraints" : [PlacementConstraint(
                    Type='memberOf',
                    Expression='attribute:deployment_type == spot' if spot_deployment else 'attribute:deployment_type == ondemand'
                )],
            }

        if 'http_interface' in config:
            container_definition_arguments['PortMappings'] = [
                PortMapping(
                    ContainerPort=int(
                        config['http_interface']['container_port']
                    )
                )
            ]
        if 'logging' not in config or 'logging' in config and config['logging'] is not None:
            container_definition_arguments['LogConfiguration'] = self._gen_log_config(service_name, "awslogs" if 'logging' not in config else config['logging'])

        if config['command'] is not None:
            container_definition_arguments['Command'] = [config['command']]

        if 'volume' in config:
            container_definition_arguments['MountPoints'] = [MountPoint(
                SourceVolume=service_name + '-efs-volume',
                ContainerPath=config['volume']['container_path']
            )]
        if launch_type == self.LAUNCH_TYPE_EC2:
            container_definition_arguments['MemoryReservation'] = int(config['memory_reservation'])
            container_definition_arguments['Memory'] = int(config['memory_reservation']) + -(-(int(config['memory_reservation']) * 50 )//100) # Celling the value

        cd = ContainerDefinition(**container_definition_arguments)

        task_role = self.template.add_resource(Role(
            service_name + "Role",
            AssumeRolePolicyDocument=PolicyDocument(
                Statement=[
                    Statement(
                        Effect=Allow,
                        Action=[AssumeRole],
                        Principal=Principal("Service", ["ecs-tasks.amazonaws.com"])
                    )
                ]
            )
        ))

        launch_type_td = {}
        if launch_type == self.LAUNCH_TYPE_FARGATE:
            launch_type_td = {
                'RequiresCompatibilities': ['FARGATE'],
                'NetworkMode': 'awsvpc',
                'Cpu': str(config['fargate']['cpu']),
                'Memory': str(config['fargate']['memory'])
            }

        if 'custom_metrics' in config:
            launch_type_td['NetworkMode'] = 'awsvpc'
        if 'volume' in config:
            launch_type_td['Volumes'] = [Volume(
                Name=service_name + '-efs-volume',
                EFSVolumeConfiguration=EFSVolumeConfiguration(
                    FilesystemId=config['volume']['efs_id'],
                    RootDirectory=config['volume']['efs_directory_path']
                )
            )]

        td = TaskDefinition(
            service_name + "TaskDefinition",
            Family=service_name + "Family",
            ContainerDefinitions=[cd],
            ExecutionRoleArn=boto3.resource('iam').Role('ecsTaskExecutionRole').arn,
            TaskRoleArn=Ref(task_role),
            Tags=Tags(Team=self.team_name, environment=self.env, task_definition_source="cloudformation"),
            **launch_type_td

        )
        if 'custom_metrics' in config:
            sd = SD(
                service_name + "ServiceRegistry",
                DnsConfig=DnsConfig(
                    RoutingPolicy="MULTIVALUE",
                    DnsRecords=[DnsRecord(
                        TTL="60",
                        Type="SRV"
                    )],
                    NamespaceId=ImportValue(
                    "{self.env}Cloudmap".format(**locals()))
                ),
                Tags=Tags(
                    {'METRICS_PATH': config['custom_metrics']['metrics_path']},
                    {'METRICS_PORT': config['custom_metrics']['metrics_port']}
                )
            )
            self.template.add_resource(sd)

        self.template.add_resource(td)
        # desired_count = self._get_desired_task_count_for_service(service_name)
        deployment_configuration = DeploymentConfiguration(
            MinimumHealthyPercent=100,
            MaximumPercent=200
        )
        if 'http_interface' in config:
            lb, target_group_name, target_group = self._add_ecs_lb(cd, service_name, config, launch_type)

            security_group_ingress = {
                'IpProtocol': 'TCP',
                'ToPort': int(config['http_interface']['container_port']),
                'FromPort': int(config['http_interface']['container_port']),
            }
            launch_type_svc = {}
            
            alb_enabled = 'alb' in config['http_interface']
            if alb_enabled:
                alb_config = config['http_interface']['alb']
                create_new_alb = alb_config.get('create_new', False)

                if create_new_alb:
                    alb, service_listener, alb_sg = self._add_alb(service_name, config, target_group_name)
                    launch_type_svc['DependsOn'] = service_listener.title
                    
                    self.template.add_output(
                        Output(
                            service_name + "URL",
                            Description="The URL at which the service is accessible",
                            Value=Sub("https://${" + alb.name + ".DNSName}")
                        )
                    )
                    if launch_type == self.LAUNCH_TYPE_FARGATE:
                        # needed for FARGATE security group creation.
                        security_group_ingress['SourceSecurityGroupId'] = Ref(alb_sg)
                else:
                    listener_arn = alb_config['listener_arn']
                    self._attach_to_existing_alb(alb_config, service_name, target_group_name)
                    alb_full_name = self.get_alb_full_name_from_listener_arn(alb_config['listener_arn'])
                    # self.create_target_group_alarms(target_group_name, target_group, alb_full_name, alb_config)
                    security_group_ingress['SourceSecurityGroupId'] = self.alb_security_group

            if launch_type == self.LAUNCH_TYPE_FARGATE:
                # if launch type is ec2, then services inherit the ec2 instance security group
                # otherwise, we need to specify a security group for the service
                if 'custom_metrics' in config:
                    launch_type_svc['ServiceRegistries'] = ServiceRegistry(
                            RegistryArn=GetAtt(sd, 'Arn'),
                            Port=int(
                                config['custom_metrics']['metrics_port'])
                        )
                else:
                    service_security_group = SecurityGroup(
                        pascalcase("FargateService" + self.env + service_name),
                        GroupName=pascalcase("FargateService" + self.env + service_name),
                        SecurityGroupIngress=[security_group_ingress],
                        VpcId=Ref(self.vpc),
                        GroupDescription=pascalcase("FargateService" + self.env + service_name),
                        Tags=Tags(Team=self.team_name, environment=self.env)
                    )
                    self.template.add_resource(service_security_group)

                launch_type_svc['NetworkConfiguration'] = NetworkConfiguration(
                    AwsvpcConfiguration=AwsvpcConfiguration(
                        Subnets=[
                            Ref(self.private_subnet1),
                            Ref(self.private_subnet2)
                        ],
                        SecurityGroups=[
                            ImportValue("{self.env}Ec2Host".format(**locals())) if 'custom_metrics' in config else Ref(service_security_group)
                        ]
                    )
                )
            else:
                if 'custom_metrics' in config:
                    launch_type_svc['ServiceRegistries'] = ServiceRegistry(
                            RegistryArn=GetAtt(sd, 'Arn'),
                            Port=int(
                                config['custom_metrics']['metrics_port'])
                        )
                    launch_type_svc['NetworkConfiguration'] = NetworkConfiguration(
                            AwsvpcConfiguration=AwsvpcConfiguration(
                                SecurityGroups=[
                                    ImportValue(
                                        "{self.env}Ec2Host".format(**locals()))
                                ],
                                Subnets=[
                                    Ref(self.private_subnet1),
                                    Ref(self.private_subnet2)
                                ]
                            )
                        )
                    launch_type_svc['PlacementStrategies'] =  self.PLACEMENT_STRATEGIES
                else:
                    launch_type_svc['Role'] = Ref(self.ecs_service_role)
                    launch_type_svc['PlacementStrategies'] = self.PLACEMENT_STRATEGIES

            svc = Service(
                service_name,
                LoadBalancers=[lb],
                Cluster=self.cluster_name,
                TaskDefinition=Ref(td),
                DesiredCount=desired_count,
                LaunchType=launch_type,
                **launch_type_svc,
                Tags=Tags(Team=self.team_name, environment=self.env),
                **placement_constraint
            )

            if autoscaling_config:
                scheduled_actions = []
                if 'scheduled_scaling' in autoscaling_config:
                    scheduled_actions = self._build_scheduled_action(svc, autoscaling_config['scheduled_scaling'])

                scalable_target = self._add_scalable_target(svc, autoscaling_config, scheduled_actions)
                # self._add_scalable_target_alarms(service_name, svc, autoscaling_config)

                if 'alb_arn' in autoscaling_config['request_count_per_target']:
                    alb_arn = autoscaling_config['request_count_per_target']['alb_arn']
                elif 'http_interface' in config and alb_enabled and create_new_alb:
                    alb_arn = alb
                elif listener_arn:
                    client = get_client_for('elbv2', self.region)
                    listeners = client.describe_listeners(
                        ListenerArns=[listener_arn]
                    )
                    alb_arn = listeners['Listeners'][0]['LoadBalancerArn']
                else:
                    raise UnrecoverableException('Unable to fetch alb arn, please provide alb_arn in config')
                self._add_alb_request_count_scaling_policy(
                    svc,
                    alb_arn,
                    target_group,
                    autoscaling_config['request_count_per_target'],
                    scalable_target
                )

            self.template.add_output(
                Output(
                    service_name + 'EcsServiceName',
                    Description='The ECS name which needs to be entered',
                    Value=GetAtt(svc, 'Name')
                )
            )
            self.template.add_resource(svc)
        else:
            launch_type_svc = {}
            if launch_type == self.LAUNCH_TYPE_FARGATE:
                # if launch type is ec2, then services inherit the ec2 instance security group
                # otherwise, we need to specify a security group for the service
                if 'custom_metrics' in config:
                    launch_type_svc = {
                        "ServiceRegistries": [ServiceRegistry(
                            RegistryArn=GetAtt(sd, 'Arn'),
                            Port=int(
                                config['custom_metrics']['metrics_port'])
                        )],
                        'NetworkConfiguration': NetworkConfiguration(
                            AwsvpcConfiguration=AwsvpcConfiguration(
                                Subnets=[
                                    Ref(self.private_subnet1),
                                    Ref(self.private_subnet2)
                                ],
                                SecurityGroups=[
                                    ImportValue(
                                        "{self.env}Ec2Host".format(**locals()))
                                ]
                            )
                        )
                    }
                else:
                    service_security_group = SecurityGroup(
                        pascalcase("FargateService" + self.env + service_name),
                        GroupName=pascalcase("FargateService" + self.env + service_name),
                        SecurityGroupIngress=[],
                        VpcId=Ref(self.vpc),
                        GroupDescription=pascalcase("FargateService" + self.env + service_name),
                        Tags=Tags(Team=self.team_name, environment=self.env)
                    )
                    self.template.add_resource(service_security_group)
                    launch_type_svc = {
                        'NetworkConfiguration': NetworkConfiguration(
                            AwsvpcConfiguration=AwsvpcConfiguration(
                                Subnets=[
                                    Ref(self.private_subnet1),
                                    Ref(self.private_subnet2)
                                ],
                                SecurityGroups=[
                                    Ref(service_security_group)
                                ]
                            )
                        )
                    }
            else:
                if 'custom_metrics' in config:
                    launch_type_svc = {
                        "ServiceRegistries": [ServiceRegistry(
                            RegistryArn=GetAtt(sd, 'Arn'),
                            Port=int(
                                config['custom_metrics']['metrics_port'])
                        )],
                        "NetworkConfiguration": NetworkConfiguration(
                            AwsvpcConfiguration=AwsvpcConfiguration(
                                SecurityGroups=[
                                    ImportValue(
                                        "{self.env}Ec2Host".format(**locals()))
                                ],
                                Subnets=[
                                    Ref(self.private_subnet1),
                                    Ref(self.private_subnet2)
                                ]
                            )
                        ),
                        'PlacementStrategies': self.PLACEMENT_STRATEGIES
                    }
                else:
                    launch_type_svc = {
                        'PlacementStrategies': self.PLACEMENT_STRATEGIES
                    }
            svc = Service(
                service_name,
                Cluster=self.cluster_name,
                TaskDefinition=Ref(td),
                DesiredCount=desired_count,
                DeploymentConfiguration=deployment_configuration,
                LaunchType=launch_type,
                **launch_type_svc,
                Tags=Tags(Team=self.team_name, environment=self.env),
                **placement_constraint
            )
            self.template.add_output(
                Output(
                    service_name + 'EcsServiceName',
                    Description='The ECS name which needs to be entered',
                    Value=GetAtt(svc, 'Name')
                )
            )
            self.template.add_resource(svc)
        self._add_service_alarms(svc)

    def _gen_log_config(self, service_name, config):
        if config == 'awslogs':
            return LogConfiguration(
                LogDriver="awslogs",
                Options={
                    'awslogs-stream-prefix': service_name,
                    'awslogs-group': '-'.join([self.env, 'logs']),
                    'awslogs-region': self.region
                }
            )
        elif config == 'fluentd':
            return LogConfiguration(
                LogDriver="fluentd",
                Options={
                    'fluentd-address': 'unix:///var/run/fluent.sock',
                    'labels': 'com.amazonaws.ecs.cluster,com.amazonaws.ecs.container-name,com.amazonaws.ecs.task-arn,com.amazonaws.ecs.task-definition-family,com.amazonaws.ecs.task-definition-version',
                    'fluentd-async': 'true'
                }
            )
        elif config == 'null':
            return LogConfiguration(
                LogDriver="none"
            )

    def _add_alb(self, service_name, config, target_group_name):
        sg_name = 'SG' + self.env + service_name
        svc_alb_sg = SecurityGroup(
            re.sub(r'\W+', '', sg_name),
            GroupName=self.env + '-' + service_name,
            SecurityGroupIngress=self._generate_alb_security_group_ingress(
                config
            ),
            VpcId=Ref(self.vpc),
            GroupDescription=Sub(service_name + "-alb-sg"),
            Tags=Tags(Team=self.team_name, environment=self.env)
        )
        self.template.add_resource(svc_alb_sg)
        alb_name = service_name + pascalcase(self.env)
        if config['http_interface']['internal']:
            alb_subnets = [
                Ref(self.private_subnet1),
                Ref(self.private_subnet2)
            ]
            scheme = "internal"
            if len(alb_name) > 32:
                alb_name = service_name[:32-len(self.env[:4])-len(scheme)] + \
                    pascalcase(self.env)[:4] + "Internal"
            else:
                alb_name += 'Internal'
                alb_name = alb_name[:32]
            alb = ALBLoadBalancer(
                'ALB' + service_name,
                Subnets=alb_subnets,
                SecurityGroups=[
                    self.alb_security_group,
                    Ref(svc_alb_sg)
                ],
                Name=alb_name,
                Tags=[
                    {'Value': alb_name, 'Key': 'Name'},
                    {"Key": "Team", "Value": self.team_name},
                    {'Key': 'environment', 'Value': self.env}
                ],
                Scheme=scheme
            )
        else:
            alb_subnets = [
                Ref(self.public_subnet1),
                Ref(self.public_subnet2)
            ]
            if len(alb_name) > 32:
                alb_name = service_name[:32-len(self.env)] + pascalcase(self.env)
            alb = ALBLoadBalancer(
                'ALB' + service_name,
                Subnets=alb_subnets,
                SecurityGroups=[
                    self.alb_security_group,
                    Ref(svc_alb_sg)
                ],
                Name=alb_name,
                Tags=[
                    {'Value': alb_name, 'Key': 'Name'},
                    {"Key": "Team", "Value": self.team_name},
                    {'Key': 'environment', 'Value': self.env}
                ]
            )

        self.template.add_resource(alb)

        target_group_action = Action(
            TargetGroupArn=Ref(target_group_name),
            Type="forward"
        )
        service_listener = self._add_service_listener(
            service_name,
            target_group_action,
            alb,
            config['http_interface']['internal']
        )
        # self._add_alb_alarms(service_name, alb)
        return alb, service_listener, svc_alb_sg
    
    def _add_ecs_lb(self, cd, service_name, config, launch_type):
        target_group_name = "TargetGroup" + service_name
        health_check_path = config['http_interface']['health_check_path'] if 'health_check_path' in config['http_interface'] else "/elb-check"
        if config['http_interface']['internal']:
            target_group_name = target_group_name + 'Internal'

        target_group_config = {}
        if launch_type == self.LAUNCH_TYPE_FARGATE or 'custom_metrics' in config:
            target_group_config['TargetType'] = 'ip'

        service_target_group = TargetGroup(
            target_group_name,
            HealthCheckPath=health_check_path,
            HealthyThresholdCount=int(config['http_interface'].get('health_check_healthy_threshold_count',DEFAULT_HEALTH_CHECK_HEALTHY_THRESHOLD_COUNT)),
            HealthCheckIntervalSeconds=int(config['http_interface'].get('health_check_interval_seconds',DEFAULT_HEALTH_CHECK_INTERVAL_SECONDS)),
            HealthCheckTimeoutSeconds=int(config['http_interface'].get('health_check_timeout_seconds',DEFAULT_HEALTH_CHECK_TIMEOUT_SECONDS)),
            UnhealthyThresholdCount=int(config['http_interface'].get('health_check_unhealthy_threshold_count',DEFAULT_HEALTH_CHECK_UNHEALTHY_THRESHOLD_COUNT)),
            TargetGroupAttributes=[
                TargetGroupAttribute(
                    Key='deregistration_delay.timeout_seconds',
                    Value=str(config['http_interface'].get('deregistration_delay',DEFAULT_TARGET_GROUP_DEREGISTRATION_DELAY))
                ),
                TargetGroupAttribute(
                    Key='load_balancing.algorithm.type',
                    Value=str(
                        config['http_interface'].get('load_balancing_algorithm', DEFAULT_LOAD_BALANCING_ALGORITHM))
                )
            ],
            VpcId=Ref(self.vpc),
            Protocol="HTTP",
            Matcher=Matcher(HttpCode="200-399"),
            Port=int(config['http_interface']['container_port']),
            **target_group_config,
            Tags=[
                {"Key": "Team", "Value": self.team_name},
                {'Key': 'environment', 'Value': self.env}
            ]
        )

        self.template.add_resource(service_target_group)

        lb = LoadBalancer(
            ContainerName=cd.Name,
            TargetGroupArn=Ref(service_target_group),
            ContainerPort=int(config['http_interface']['container_port'])
        )
        return lb, target_group_name, service_target_group
    
    def _attach_to_existing_alb(self, alb_config,  service_name , target_group_name):
        conditions = []
        if 'host' in alb_config:
            conditions.append(
                Condition(
                    Field="host-header",
                    HostHeaderConfig=HostHeaderConfig(
                        Values=[alb_config['host']],
                    ),
                )
            )
        if 'path' in alb_config:
            conditions.append(
                Condition(
                    Field="path-pattern",
                    PathPatternConfig=PathPatternConfig(
                        Values=[alb_config['path']],
                    ),
                )
            )

        priority = alb_config['priority']
        self.template.add_resource(
            ListenerRule(
                service_name + "ListenerRule",
                ListenerArn=alb_config['listener_arn'],
                Priority=int(priority),
                Conditions=conditions,
                Actions=[ListenerRuleAction(
                    Type="forward",
                    TargetGroupArn=Ref(target_group_name),
                )]
            )
        )
        
    
    def get_alb_full_name_from_listener_arn(self, listener_arn):
        return "/".join(listener_arn.split('/')[1:-1])

    def _add_service_listener(self, service_name, target_group_action,
                              alb, internal):
        ssl_cert = Certificate(CertificateArn=self.ssl_certificate_arn)
        service_listener = Listener(
            "SslLoadBalancerListener" + service_name,
            Protocol="HTTPS",
            DefaultActions=[target_group_action],
            LoadBalancerArn=Ref(alb),
            Port=443,
            Certificates=[ssl_cert],
            SslPolicy="ELBSecurityPolicy-FS-1-2-Res-2019-08"
        )
        self.template.add_resource(service_listener)
        if internal:
            # Allow HTTP traffic on internal services
            http_service_listener = Listener(
                "LoadBalancerListener" + service_name,
                Protocol="HTTP",
                DefaultActions=[target_group_action],
                LoadBalancerArn=Ref(alb),
                Port=80
            )
            self.template.add_resource(http_service_listener)
        else:
            # Redirect HTTP to HTTPS on external services
            redirection_config = RedirectConfig(
                StatusCode='HTTP_301',
                Protocol='HTTPS',
                Port='443'
            )
            http_redirection_action = Action(
                RedirectConfig=redirection_config,
                Type="redirect"
            )
            http_redirection_listener = Listener(
                "LoadBalancerRedirectionListener" + service_name,
                Protocol="HTTP",
                DefaultActions=[http_redirection_action],
                LoadBalancerArn=Ref(alb),
                Port=80
            )
            self.template.add_resource(http_redirection_listener)
        return service_listener

    # def create_target_group_alarms(self, target_group_name, target_group, alb_full_name, alb_config):
    #     unhealthy_alarm = Alarm(
    #         'TargetGroupUnhealthyHostAlarm' + target_group_name,
    #         EvaluationPeriods=1,
    #         Dimensions=[
    #             MetricDimension(
    #                 Name='LoadBalancer',
    #                 Value=alb_full_name
    #             ),
    #             MetricDimension(
    #                 Name='TargetGroup',
    #                 Value=GetAtt(target_group, 'TargetGroupFullName')
    #             )
    #         ],
    #         AlarmActions=[Ref(self.notification_sns_arn)],
    #         OKActions=[Ref(self.notification_sns_arn)],
    #         AlarmDescription='Triggers if any host is marked unhealthy',
    #         Namespace='AWS/ApplicationELB',
    #         Period=60,
    #         ComparisonOperator='GreaterThanOrEqualToThreshold',
    #         Statistic='Sum',
    #         Threshold='1',
    #         MetricName='UnHealthyHostCount',
    #         TreatMissingData='notBreaching'
    #     )
    #     self.template.add_resource(unhealthy_alarm)

        # high_5xx_alarm = Alarm(
        #     'HighTarget5XXAlarm' + target_group_name,
        #     EvaluationPeriods=1,
        #     Dimensions=[
        #         MetricDimension(
        #             Name='LoadBalancer',
        #             Value=alb_full_name
        #         ),
        #         MetricDimension(
        #             Name='TargetGroup',
        #             Value=GetAtt(target_group, 'TargetGroupFullName')
        #         )
        #     ],
        #     AlarmActions=[Ref(self.notification_sns_arn)],
        #     OKActions=[Ref(self.notification_sns_arn)],
        #     AlarmDescription='Triggers if target returns 5xx error code',
        #     Namespace='AWS/ApplicationELB',
        #     Period=60,
        #     ComparisonOperator='GreaterThanOrEqualToThreshold',
        #     Statistic='Sum',
        #     Threshold=int(alb_config.get('target_5xx_error_threshold', 10)),
        #     MetricName='HTTPCode_Target_5XX_Count',
        #     TreatMissingData='notBreaching'
        # )
        # self.template.add_resource(high_5xx_alarm)

        # latency_alarms = self._get_latency_alarms(alb_config, alb_full_name,
        #                                           target_group, target_group_name)

        # for alarm in latency_alarms:
        #     self.template.add_resource(alarm)

    # def _get_latency_alarms(self, alb_config, alb_full_name, target_group, target_group_name):
    #     high_p95_latency_alarm = Alarm(
    #         'HighP95LatencyAlarm' + target_group_name,
    #         EvaluationPeriods=int(alb_config.get('target_p95_latency_evaluation_periods', 5)),
    #         Dimensions=[
    #             MetricDimension(
    #                 Name='LoadBalancer',
    #                 Value=alb_full_name
    #             ),
    #             MetricDimension(
    #                 Name='TargetGroup',
    #                 Value=GetAtt(target_group, 'TargetGroupFullName')
    #             )
    #         ],
    #         AlarmActions=[Ref(self.notification_sns_arn)],
    #         OKActions=[Ref(self.notification_sns_arn)],
    #         AlarmDescription='Triggers if p95 latency of target group is higher than threshold',
    #         Namespace='AWS/ApplicationELB',
    #         Period=int(alb_config.get('target_p95_latency_period_seconds', 60)),
    #         ComparisonOperator='GreaterThanOrEqualToThreshold',
    #         ExtendedStatistic='p95',
    #         Threshold=int(alb_config.get('target_p95_latency_threshold_seconds', 15)),
    #         MetricName='TargetResponseTime',
    #         TreatMissingData='notBreaching'
    #     )
    #     return [high_p95_latency_alarm]


#     def _add_alb_alarms(self, service_name, alb):
#         unhealthy_alarm = Alarm(
#             'ElbUnhealthyHostAlarm' + service_name,
#             EvaluationPeriods=1,
#             Dimensions=[
#                 MetricDimension(
#                     Name='LoadBalancer',
#                     Value=GetAtt(alb, 'LoadBalancerFullName')
#                 )
#             ],
#             AlarmActions=[Ref(self.notification_sns_arn)],
#             OKActions=[Ref(self.notification_sns_arn)],
#             AlarmDescription='Triggers if any host is marked unhealthy',
#             Namespace='AWS/ApplicationELB',
#             Period=60,
#             ComparisonOperator='GreaterThanOrEqualToThreshold',
#             Statistic='Sum',
#             Threshold='1',
#             MetricName='UnHealthyHostCount',
#             TreatMissingData='notBreaching'
#         )
#         self.template.add_resource(unhealthy_alarm)
#         rejected_connections_alarm = Alarm(
#             'ElbRejectedConnectionsAlarm' + service_name,
#             EvaluationPeriods=1,
#             Dimensions=[
#                 MetricDimension(
#                     Name='LoadBalancer',
#                     Value=GetAtt(alb, 'LoadBalancerFullName')
#                 )
#             ],
#             AlarmActions=[Ref(self.notification_sns_arn)],
#             OKActions=[Ref(self.notification_sns_arn)],
#             AlarmDescription='Triggers if load balancer has \
# rejected connections because the load balancer \
# had reached its maximum number of connections.',
#             Namespace='AWS/ApplicationELB',
#             Period=60,
#             ComparisonOperator='GreaterThanOrEqualToThreshold',
#             Statistic='Sum',
#             Threshold='1',
#             MetricName='RejectedConnectionCount',
#             TreatMissingData='notBreaching'
#         )
#         self.template.add_resource(rejected_connections_alarm)
#         http_code_elb5xx_alarm = Alarm(
#             'ElbHTTPCodeELB5xxAlarm' + service_name,
#             EvaluationPeriods=1,
#             Dimensions=[
#                 MetricDimension(
#                     Name='LoadBalancer',
#                     Value=GetAtt(alb, 'LoadBalancerFullName')
#                 )
#             ],
#             AlarmActions=[Ref(self.notification_sns_arn)],
#             OKActions=[Ref(self.notification_sns_arn)],
#             AlarmDescription='Triggers if 5xx response originated \
# from load balancer',
#             Namespace='AWS/ApplicationELB',
#             Period=60,
#             ComparisonOperator='GreaterThanOrEqualToThreshold',
#             Statistic='Sum',
#             Threshold='3',
#             MetricName='HTTPCode_ELB_5XX_Count',
#             TreatMissingData='notBreaching'
#         )
#         self.template.add_resource(http_code_elb5xx_alarm)

    def _generate_alb_security_group_ingress(self, config):
        ingress_rules = []
        for access_ip in config['http_interface']['restrict_access_to']:
            if access_ip.find('/') == -1:
                access_ip = access_ip + '/32'
            ingress_rules.append({
                'ToPort': 80,
                'IpProtocol': 'TCP',
                'FromPort': 80,
                'CidrIp': access_ip
            })
            ingress_rules.append({
                'ToPort': 443,
                'IpProtocol': 'TCP',
                'FromPort': 443,
                'CidrIp': access_ip
            })
        return ingress_rules

    def _add_ecs_service_iam_role(self):
        role_name = Sub('ecs-svc-${AWS::StackName}-${AWS::Region}')
        assume_role_policy = {
            u'Statement': [
                {
                    u'Action': [u'sts:AssumeRole'],
                    u'Effect': u'Allow',
                    u'Principal': {
                        u'Service': [u'ecs.amazonaws.com']
                    }
                }
            ]
        }
        self.ecs_service_role = Role(
            'ECSServiceRole',
            Path='/',
            ManagedPolicyArns=[
                'arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceRole'
            ],
            RoleName=role_name,
            AssumeRolePolicyDocument=assume_role_policy
        )
        self.template.add_resource(self.ecs_service_role)

    def _add_service_outputs(self):
        self.template.add_output(Output(
            "CloudliftOptions",
            Description="Options used with cloudlift when \
building this service",
            Value=json.dumps(
                self.configuration,
                cls=DecimalEncoder
            )
        ))
        self._add_stack_outputs()

    def _add_service_parameters(self):
        self.notification_sns_arn = Parameter(
            "NotificationSnsArn",
            Description='',
            Type="String",
            Default=self.notifications_arn)
        self.template.add_parameter(self.notification_sns_arn)
        self.vpc = Parameter(
            "VPC",
            Description='',
            Type="AWS::EC2::VPC::Id",
            Default=list(
                filter(
                    lambda x: x['OutputKey'] == "VPC",
                    self.environment_stack['Outputs']
                )
            )[0]['OutputValue']
        )
        self.template.add_parameter(self.vpc)
        self.public_subnet1 = Parameter(
            "PublicSubnet1",
            Description='',
            Type="AWS::EC2::Subnet::Id",
            Default=list(
                filter(
                    lambda x: x['OutputKey'] == "PublicSubnet1",
                    self.environment_stack['Outputs']
                )
            )[0]['OutputValue']
        )
        self.template.add_parameter(self.public_subnet1)
        self.public_subnet2 = Parameter(
            "PublicSubnet2",
            Description='',
            Type="AWS::EC2::Subnet::Id",
            Default=list(
                filter(
                    lambda x: x['OutputKey'] == "PublicSubnet2",
                    self.environment_stack['Outputs']
                )
            )[0]['OutputValue']
        )
        self.template.add_parameter(self.public_subnet2)
        self.private_subnet1 = Parameter(
            "PrivateSubnet1",
            Description='',
            Type="AWS::EC2::Subnet::Id",
            Default=list(
                filter(
                    lambda x: x['OutputKey'] == "PrivateSubnet1",
                    self.environment_stack['Outputs']
                )
            )[0]['OutputValue']
        )
        self.template.add_parameter(self.private_subnet1)
        self.private_subnet2 = Parameter(
            "PrivateSubnet2",
            Description='',
            Type="AWS::EC2::Subnet::Id",
            Default=list(
                filter(
                    lambda x: x['OutputKey'] == "PrivateSubnet2",
                    self.environment_stack['Outputs']
                )
            )[0]['OutputValue']
        )
        self.template.add_parameter(self.private_subnet2)
        self.template.add_parameter(Parameter(
            "Environment",
            Description='',
            Type="String",
            Default="production"
        ))
        self.alb_security_group = list(
            filter(
                lambda x: x['OutputKey'] == "SecurityGroupAlb",
                self.environment_stack['Outputs']
            )
        )[0]['OutputValue']

    def _fetch_current_desired_count(self):
        stack_name = get_service_stack_name(self.env, self.application_name)
        self.desired_counts = {}
        try:
            stack = region_service.get_client_for(
                'cloudformation',
                self.env
            ).describe_stacks(StackName=stack_name)['Stacks'][0]
            ecs_service_outputs = filter(
                lambda x: x['OutputKey'].endswith('EcsServiceName'),
                stack['Outputs']
            )
            ecs_service_names = []
            for service_name in ecs_service_outputs:
                ecs_service_names.append({
                    "key": service_name['OutputKey'],
                    "value": service_name['OutputValue']
                })
            ecs_client = EcsClient(None, None, self.region)
            for service_name in ecs_service_names:
                deployment = DeployAction(
                    ecs_client,
                    self.cluster_name,
                    service_name["value"]
                )
                actual_service_name = service_name["key"]. \
                    replace("EcsServiceName", "")
                self.desired_counts[actual_service_name] = deployment. \
                    service.desired_count
            log("Existing service counts: " + str(self.desired_counts))
        except Exception:
            log_bold("Could not find existing services.")

    def _get_desired_task_count_for_service(self, service_name, min_count=0):
        return max(self.desired_counts.get(service_name, 0), min_count)

    @property
    def ecr_image_uri(self):
        return str(self.account_id) + ".dkr.ecr." + \
               self.region + ".amazonaws.com/" + \
               self.repo_name

    @property
    def account_id(self):
        return get_account_id()

    @property
    def repo_name(self):
        return self.application_name + '-repo'

    @property
    def notifications_arn(self):
        """
        Get the SNS arn either from service configuration or the cluster
        """
        if 'notifications_arn' in self.configuration:
            return self.configuration['notifications_arn']
        else:
            return TemplateGenerator.notifications_arn.fget(self)
