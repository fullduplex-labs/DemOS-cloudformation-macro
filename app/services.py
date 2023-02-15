#
# Copyright 2023 Full Duplex Media, LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import _globals as DemOS

def make():
  make_iam_ExecutionRole('Default')

  make_service_VpnGateway()

def make_iam_ExecutionRole(service):
  resourcePrefix = 'RoleEcsExecution'

  if type(service) is not str and not service.get('ExecutionRole'):
    service['ExecutionRole'] = dict(
      ResourceName = f'{resourcePrefix}Default'
    )
    return 

  resource = dict(
    Type = 'AWS::IAM::Role',
    Properties = dict(
      Path = f'/{DemOS.Namespace}/{DemOS.Project}/{DemOS.Name}/',
      AssumeRolePolicyDocument = dict(
        Version = '2012-10-17',
        Statement = [
          dict(
            Effect = 'Allow',
            Principal = dict(Service = 'ecs-tasks.amazonaws.com'),
            Action = 'sts:AssumeRole'
          )
        ]
      ),
      Policies = [
        dict(
          PolicyName = 'ecs.base',
          PolicyDocument = dict(
            Version = '2012-10-17',
            Statement = [
              {
                'Effect': 'Allow',
                'Action': [
                  'logs:CreateLogStream',
                  'logs:PutLogEvents'
                ],
                'Resource': [
                  DemOS.Logs["Services"]["Ecs"]["Arn"],
                  f'{DemOS.Logs["Services"]["Ecs"]["Arn"]}:log-stream:*'
                ]
              },
              {
                'Effect': 'Allow',
                'Action': 'ecr:GetAuthorizationToken',
                'Resource': '*'
              },
              {
                'Effect': 'Allow',
                'Action': [
                  'ecr:BatchCheckLayerAvailability',
                  'ecr:GetDownloadUrlForLayer',
                  'ecr:BatchGetImage'
                ],
                'Resource': f'{DemOS.RegistryEcrArn}/*'
              }
            ]
          )
        )
      ]
    )
  )

  if type(service) is str:
    resourceName = f'{resourcePrefix}{service}'

  else:
    resourceName = f'{resourcePrefix}{service["Name"]}'
    service['ExecutionRole']['ResourceName'] = resourceName

    if service['ExecutionRole'].get('DependsOn'):
      resource['DependsOn'] = service['ExecutionRole']['DependsOn']

    resource['Properties']['Policies'].append(dict(
      PolicyName = f'ecs.{service}',
      PolicyDocument = dict(
        Version = '2012-10-17',
        Statement = service['ExecutionRole']['Policy']
      )
    ))

  DemOS.resource(resourceName, resource)

def make_service_VpnGateway():

  DemOS.output(
    'VpnProfile',
    {'Fn::GetAtt': f'{DemOS.certificates["VpnGateway"]}.Profile'}
  )

  make_service(dict(
    Name = 'VpnGateway',
    Task = dict(
      Instance = 'Manager',
      NetworkMode = 'host',
      Mounts = {
        'ca-cert': f'{DemOS.certificatePath}/authority/cert.pem',
        'external-key': f'{DemOS.certificatePath}/external/key.pem',
        'external-cert': f'{DemOS.certificatePath}/external/cert.pem',
        'internal-key': f'{DemOS.certificatePath}/internal/key.pem',
        'internal-cert': f'{DemOS.certificatePath}/internal/cert.pem',
        'diffie-hellman': f'{DemOS.certificatePath}/diffiehellman/params.pem',
        'tls-key': f'{DemOS.certificatePath}/vpngateway/key.pem'
      },
      Containers = [
        dict(
          Name = 'vpn',
          Image = f'{DemOS.RegistryEcr}/vpn-gateway:{DemOS.Version}',
          LinuxParameters = dict(
            Capabilities = dict(
              Add = ['NET_ADMIN']
            ),
            Devices = [
              dict(
                HostPath = '/dev/net/tun',
                Permissions = ['read', 'write', 'mknod']
              )
            ]
          ),
          HealthCheck = dict(
            StartPeriod = 300,
            Command = ['CMD-SHELL', 'pidof openvpn']
          ),
          Environment = [
            dict(Name = 'PrivateDomain', Value = DemOS.PrivateDomain),
            dict(Name = 'PublicDomain', Value = DemOS.PublicDomain),
            dict(Name = 'SubnetPortalCidr', Value = DemOS.Subnets['Portal']),
            dict(Name = 'SubnetOpsCidr', Value = DemOS.Subnets['Ops']),
            dict(Name = 'VpnGatewayCidr', Value = DemOS.Subnets['Vpn']),
            dict(Name = 'VpnDevice', Value = 'eth0'),
            dict(Name = 'VpnLocalIp', Value = {
              'Fn::GetAtt': 'InstanceManager.PrivateIp'
            })
          ],
          MountPoints = [
            'ca-cert:/etc/openvpn/server/ca.crt',
            'external-key:/etc/openvpn/server/server.key',
            'external-cert:/etc/openvpn/server/server.crt',
            'diffie-hellman:/etc/openvpn/server/dhparams.pem',
            'internal-key:/etc/openvpn/client/client.key',
            'internal-cert:/etc/openvpn/client/client.crt',
            'tls-key:/etc/openvpn/server/vpn.key'
          ]
        )
      ]
    )
  ))

def make_service(service):
  service['ResourceName'] = f'EcsService{service["Name"]}'

  make_iam_ExecutionRole(service)

  if service.get('Role'):
    make_iam_TaskRole(service)

  if DemOS.State == 'On':
    make_ecs_TaskDefinition(service)
    make_ecs_Service(service)

def make_iam_TaskRole(service):
  resourceName = f'RoleEcsTask{service["Name"]}'
  service['Role']['ResourceName'] = resourceName

  role = service['Role']

  resource = dict(
    Type = 'AWS::IAM::Role',
    Properties = dict(
      Path = f'/{DemOS.Namespace}/{DemOS.Project}/{DemOS.Name}/',
      AssumeRolePolicyDocument = dict(
        Version = '2012-10-17',
        Statement = [
          dict(
            Effect = 'Allow',
            Principal = dict(Service = 'ecs-tasks.amazonaws.com'),
            Action = 'sts:AssumeRole'
          )
        ]
      ),
      Policies = [
        dict(
          PolicyName = 'ecs.task',
          PolicyDocument = dict(
            Version = '2012-10-17',
            Statement = role['Policy']
          )
        )
      ]
    )
  )

  if role.get('DependsOn'):
    resource['DependsOn'] = role['DependsOn']

  DemOS.resource(resourceName, resource)

def make_ecs_TaskDefinition(service):
  resourceName = f'EcsTaskDef{service["Name"]}'
  service['TaskDefinition'] = resourceName

  task = service['Task']
  platform = task.get('RequiresCompatibilities', ['EC2'])

  resource = dict(
    Type = 'AWS::ECS::TaskDefinition',
    DependsOn = [
      service['ExecutionRole']['ResourceName']
    ],
    Properties = dict(
      ExecutionRoleArn = {
        'Fn::GetAtt': f'{service["ExecutionRole"]["ResourceName"]}.Arn'
      },
      NetworkMode = task.get('NetworkMode', 'awsvpc'),
      RequiresCompatibilities = platform,
      ContainerDefinitions = []
    )
  )

  if service.get('Role'):
    resource['Properties']['TaskRoleArn'] = {
      'Fn::GetAtt': f'{service["Role"]["ResourceName"]}.Arn'
    }
    resource['DependsOn'].append(service['Role']['ResourceName'])

  if task.get('DependsOn'):
    resource['DependsOn'] += task['DependsOn']

  if task.get('Instance'):
    resource['DependsOn'].append(f'Instance{task["Instance"]}')

  if task.get('Mounts'):
    resource['Properties']['Volumes'] = []
    for name, mount in task['Mounts'].items():
      resource['Properties']['Volumes'].append(dict(
        Name = name,
        Host = dict(SourcePath = mount)
      ))

  for container in task['Containers']:
    definition = dict(
      Name = container['Name'],
      Image = container['Image'],
      Essential = container.get('Essential', True),
      HealthCheck = dict(
        StartPeriod = container['HealthCheck'].get('StartPeriod', 30),
        Interval = container['HealthCheck'].get('Interval', 30),
        Retries = container['HealthCheck'].get('Retries', 2),
        Command = container['HealthCheck']['Command']
      ),
      LogConfiguration = dict(
        LogDriver = 'awslogs',
        Options = {
          'awslogs-region': DemOS.Region,
          'awslogs-group': DemOS.Logs['Services']['Ecs']['Name'],
          'awslogs-stream-prefix': service['Name']
        }
      )
    )

    if len(platform) == 1 and platform[0] == 'EC2':
      definition['Hostname'] = container['Name']
      definition['MemoryReservation'] = container.get('MemoryReservation', 64)

    if container.get('LinuxParameters'):
      definition['LinuxParameters'] = container['LinuxParameters']

    if container.get('Environment'):
      definition['Environment'] = container['Environment']

    if container.get('MountPoints'):
      definition['MountPoints'] = []
      for mount in container['MountPoints']:
        mount = mount.split(':')
        definition['MountPoints'].append(dict(
          SourceVolume = mount[0],
          ContainerPath = mount[1],
          ReadOnly = True if (len(mount) == 2 or mount[2] != 'rw') else False
        ))

    resource['Properties']['ContainerDefinitions'].append(definition)

  DemOS.resource(resourceName, resource)

def make_ecs_Service(service):
    resource = dict(
      Type = 'AWS::ECS::Service',
      DependsOn = ['Cluster', service['TaskDefinition']],
      Properties = dict(
        TaskDefinition = {'Ref': service['TaskDefinition']},
        Cluster = {'Fn::GetAtt': 'Cluster.Arn'},
        DeploymentController = dict(Type = 'ECS'),
        EnableECSManagedTags = True,
        PropagateTags = 'SERVICE',
        Tags = [
          dict(Key = 'Name', Value = f'{DemOS.TagPrefix}-{service["Name"]}')
        ]
      )
    )

    if service['Task'].get('Instance'):
      instanceName = f'Instance{service["Task"]["Instance"]}'

      resource['DependsOn'].append(f'Wait{instanceName}')
      resource['Properties'] = resource['Properties'] | dict(
        LaunchType = 'EC2',
        SchedulingStrategy = 'REPLICA',
        DesiredCount = 1,
        DeploymentConfiguration = dict(
          MaximumPercent = 100,
          MinimumHealthyPercent = 0
        ),
        PlacementConstraints = [
          dict(
            Type = 'memberOf',
            Expression = {'Fn::Sub': f'ec2InstanceId == ${{{instanceName}}}'}
          )
        ]
      )

    DemOS.resource(service['ResourceName'], resource)
