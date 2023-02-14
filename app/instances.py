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
from textwrap import dedent

import _globals as DemOS
import foundation

def make():
  make_ec2_KeyPair()

  make_manager()
  make_workers()

def make_ec2_KeyPair():
  resourceName = 'KeyPairInstances'
  DemOS.keyPair = resourceName

  DemOS.resource('RSAKeyInstances', dict(
    Type = 'Custom::RSAKey',
    Properties = dict(
      Name = f'/{DemOS.Namespace}/{DemOS.Project}/{DemOS.Name}/instances/key',
      ServiceToken = DemOS.SecretProvider
    )
  ))

  DemOS.resource(resourceName,  dict(
    Type = 'Custom::KeyPair',
    DependsOn = 'RSAKeyInstances',
    Properties = dict(
      Name = f'{DemOS.Namespace}-{DemOS.Project}-{DemOS.Name}'.lower(),
      PublicKeyMaterial = {'Fn::GetAtt': 'RSAKeyInstances.PublicKey'},
      ServiceToken = DemOS.SecretProvider
    )
  ))

def make_manager():
  instance = dict(
    Label = 'Manager',
    InstanceType = 't4g.nano',
    Zone = 1,
    Interfaces = ['portal'],
    DependsOn = [
      DemOS.certificatePackage
    ],
    Environment = dict(
      InstanceType = 'manager',
      SubnetOpsCidr = DemOS.Subnets['Ops'],
      SubnetPrivateCidr = DemOS.Subnets['Private'],
      CertificatePackage = {'Fn::GetAtt': f'{DemOS.certificatePackage}.Url'}
    ),
    Role = dict(
      DependsOn = [
        DemOS.certificatePackage
      ],
      Policy = [
        {
          'Effect': 'Allow',
          'Action': 's3:GetObject',
          'Resource': {'Fn::GetAtt': f'{DemOS.certificatePackage}.Arn'}
        }
      ]
    )
  )

  make_iam_InstanceProfile(instance)

  if DemOS.State == 'On':
    make_instance(instance)

    for subnet in DemOS.subnets.values():
      if not subnet['Public']:
        foundation.make_ec2_Route(subnet, dict(
          Default = True,
          Instance = instance['ResourceName']
        ))

def make_workers():
  instances = {}

  defaults = dict(
    Label = 'Worker',
    InstanceType = 't4g.nano',
    Zone = 1,
    Interfaces = ['servers'],
    DependsOn = [
      'WaitInstanceManager'
    ],
    Environment = dict(
      InstanceType = 'worker'
    )
  )

  make_iam_InstanceProfile(defaults)

  for w in DemOS.Workers:
    worker = DemOS.deepCopy(defaults) | w

    label = worker['Label'] = worker['Label'].title()
    if instances.get(label) is None: instances[label] = []

    count = worker.get('Count', 1)
    for i in range(1, count+1): instances[label].append(worker)

  if DemOS.State == 'On':
    for label in instances:
      for i in range(0, len(instances[label])):
        make_instance(instances[label][i], i+1)

def make_iam_InstanceProfile(instance):
  instance['Profile'] = f'ProfileInstance{instance["Label"]}'

  make_iam_Role(instance)

  DemOS.resource(instance['Profile'], dict(
    Type = 'AWS::IAM::InstanceProfile',
    DependsOn = instance['RoleName'],
    Properties = dict(
      Roles = [
        {'Ref': instance['RoleName']}
      ]
    )
  ))

def make_iam_Role(instance):
  instance['RoleName'] = f'RoleInstance{instance["Label"]}'

  dependsOn = [
    'FileSystem',
    'AccessPoint'
  ]

  policies = [
    dict(
      PolicyName = 'ec2.base',
      PolicyDocument = dict(
        Version = '2012-10-17',
        Statement = [
          {
            "Effect": "Allow",
            "Action": [
              "ec2:DescribeTags",
              "ecs:DiscoverPollEndpoint",
              "ecr:GetAuthorizationToken"
            ],
            "Resource": '*'
          },
          {
            "Effect": "Allow",
            "Action": [
              "ecs:DeregisterContainerInstance",
              "ecs:Poll",
              "ecs:RegisterContainerInstance",
              "ecs:StartTelemetrySession",
              "ecs:UpdateContainerInstancesState",
              "ecs:Submit*",
              "ecr:BatchCheckLayerAvailability",
              "ecr:GetDownloadUrlForLayer",
              "ecr:BatchGetImage"
            ],
            "Resource": [
              DemOS.ClusterEcsArn,
              f'{DemOS.ClusterEcsInstanceArn}/*',
              f'{DemOS.RegistryEcrArn}/*',
            ]
          },
          {
            'Effect': 'Allow',
            'Action': [
              'elasticfilesystem:ClientMount',
              'elasticfilesystem:ClientWrite'
            ],
            'Resource': {'Fn::GetAtt': 'FileSystem.Arn'},
            'Condition': {
              'StringEquals': {
                'elasticfilesystem:AccessPointArn': {
                  'Fn::GetAtt': 'AccessPoint.Arn'
                }
              }
            }
          },
          {
            'Effect': 'Allow',
            'Action': [
              'logs:CreateLogStream',
              'logs:PutLogEvents'
            ],
            'Resource': [
              DemOS.Logs["Services"]["Instances"]["Arn"],
              f'{DemOS.Logs["Services"]["Instances"]["Arn"]}:log-stream:*'
            ]
          }
        ]
      )
    )
  ]

  if instance.get('Role'):
    if instance['Role'].get('DependsOn'):
      dependsOn += instance['Role']['DependsOn']

    if instance['Role'].get('Policy'):
      policies.append(dict(
        PolicyName = f'ec2.instance',
        PolicyDocument = dict(
          Version = '2012-10-17',
          Statement = instance['Role']['Policy']
        )
      ))

  DemOS.resource(instance['RoleName'], dict(
    Type = 'AWS::IAM::Role',
    DependsOn = dependsOn,
    Properties = dict(
      Path = f'/{DemOS.Namespace}/{DemOS.Project}/{DemOS.Name}/',
      AssumeRolePolicyDocument = dict(
        Version = '2012-10-17',
        Statement = [
          dict(
            Effect = 'Allow',
            Principal = dict(Service = 'ec2.amazonaws.com'),
            Action = 'sts:AssumeRole'
          )
        ]
      ),
      Policies = policies
    )
  ))

def make_instance(instance, id=None):
  id = '' if id is None else id

  resourceName = f'Instance{instance["Label"]}{id}'

  instance['ResourceName'] = resourceName
  instance['HostName'] = f'{instance["Label"]}{id}'.lower()
  instance['interfaces'] = []
  instance['eips'] = []

  for index in range(0, len(instance['Interfaces'])):
    subnetLabel = instance['Interfaces'][index]
    subnet = DemOS.subnets[subnetLabel]

    if not set(subnet['DefaultRoutes']).issubset(instance['DependsOn']):
      instance['DependsOn'] += subnet['DefaultRoutes']

    if index == 0: continue

    make_ec2_NetworkInterface(instance, subnet, index)
    make_ec2_NetworkInterfaceAttachment(instance, index)

    if subnet['Public']:
      make_ec2_EIP(instance, index)
      make_ec2_EIPAssociation(instance, index)

  make_cfn_WaitCondition(instance)
  make_ec2_Instance(instance)
  make_route53_RecordSets(instance)

def make_ec2_NetworkInterface(instance, subnet, index=1):
  resourceName = f'{instance["ResourceName"]}Interface{index}'

  instance['interfaces'][index] = resourceName
  instance['DependsOn'].append(resourceName)

  groupSet = [
    {'Ref': 'SecurityGroupLocal'}
  ]
  if subnet['Public'] and instance['Label'] == 'Manager':
    groupSet.append({'Ref': 'SecurityGroupSudo'})

  DemOS.resource(resourceName, dict(
    Type = 'AWS::EC2::NetworkInterface',
    Properties = dict(
      Description = f'{DemOS.TagPrefix}-{instance["ResourceName"]}-{index}',
      GroupSet = groupSet,
      SubnetId = {'Ref': subnet['Names'][0]},
      Tags = [
        dict(
          Key = 'Name',
          Value = f'{DemOS.TagPrefix}-{instance["ResourceName"]}-{index}'
        )
      ]
    )
  ))

def make_ec2_NetworkInterfaceAttachment(instance, index):
  resourceName = f'{instance["ResourceName"]}InterfaceAttachment{index}'

  DemOS.resource(resourceName, dict(
    Type = 'AWS::EC2::NetworkInterfaceAttachment',
    DependsOn = [
      instance['interfaces'][index],
      instance['ResourceName']
    ],
    Properties = dict( 
      DeleteOnTermination = True,
      DeviceIndex = index,
      InstanceId = {'Ref': instance['ResourceName']},
      NetworkInterfaceId = {'Ref': instance['interfaces'][index]}
    )
  ))

def make_ec2_EIP(instance, index=1):
  resourceName = f'{instance["ResourceName"]}EIP{index}'

  instance['eips'][index] = resourceName

  DemOS.resource(resourceName, dict(
    Type = 'AWS::EC2::EIP',
    Properties = dict(
      Domain = 'vpc',
      Tags = [
        dict(
          Key = 'Name',
          Value = f'{DemOS.TagPrefix}-{instance["ResourceName"]}-{index}'
        )
      ]
    )
  ))

def make_ec2_EIPAssociation(instance, index=1):
  resourceName = f'{instance["ResourceName"]}EIPAssociation{index}'
  instance['DependsOn'].append(resourceName)

  elasticIp = instance['eips'][index]
  interface = instance['interfaces'][index]

  DemOS.resource(resourceName, dict(
    Type = 'AWS::EC2::EIPAssociation',
    DependsOn = [
      elasticIp,
      interface
    ],
    Properties = dict(
      AllocationId = {'Fn::GetAtt': f'{elasticIp}.AllocationId'},
      NetworkInterfaceId = {'Ref': interface}
    )
  ))

def make_cfn_WaitCondition(instance):
  instance['Handle'] = f'WaitHandle{instance["ResourceName"]}'

  DemOS.resource(instance['Handle'], dict(
    Type = 'AWS::CloudFormation::WaitConditionHandle',
    Properties = {}
  ))

  DemOS.resource(f'Wait{instance["ResourceName"]}', dict(
    Type = 'AWS::CloudFormation::WaitCondition',
    DependsOn = [
      instance['Handle'],
      instance['ResourceName']
    ],
    Properties = dict(
      Count = 1,
      Handle = {'Ref': instance['Handle']},
      Timeout = 600
    )
  ))

def make_ec2_Instance(instance):
  instance['DependsOn'] += [
    'Cluster',
    'SecurityGroupSudo',
    'SecurityGroupLocal',
    'FileSystem',
    'MountTarget',
    'AccessPoint',
    DemOS.keyPair,
    instance['Profile'],
    instance['Handle']
  ]

  initEnvironment = instance.get('Environment', {}) | dict(
    Version = DemOS.Version,
    AwsRegion = DemOS.Region,
    AccessPoint = {'Ref': 'AccessPoint'},
    FileSystem = {'Ref': 'FileSystem'},
    ServicesLogGroup = DemOS.Logs['Services']['Instances']['Name'],
    AwsRegistry = DemOS.RegistryEcr,
    InstanceLabel = instance['Label'].lower(),
    InstanceName = instance['HostName']
  )

  subnet = instance['Interfaces'][0]
  groupSet = [{'Ref': 'SecurityGroupLocal'}]
  if DemOS.subnets[subnet]['Public']:
    groupSet.append({'Ref': 'SecurityGroupSudo'})

  networkInterfaces = [
    dict(
      DeviceIndex = 0,
      AssociatePublicIpAddress = DemOS.subnets[subnet]['Public'],
      DeleteOnTermination = True,
      GroupSet = groupSet,
      SubnetId = {'Ref': DemOS.subnets[subnet]['Names'][0]}
    )
  ]

  cfnConfig = dict(
    sources = {
      '/opt/awscli': 'https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip'
    },
    files = {
      '/etc/ecs/ecs.config': dict(
        encoding = 'base64',
        content = DemOS.j2('instances/ecs.config', b64=True)
      ),
      '/opt/demos/init.sh': dict(
        mode = '000700',
        encoding = 'base64',
        content = DemOS.include('instances/init.sh', b64=True)
      )
    },
    commands = dict(
      awscli = dict(
        command = '/opt/awscli/aws/install'
      ),
      init = dict(
        command = '/opt/demos/init.sh',
        env = initEnvironment
      )
    )
  )

  if instance.get('Packages'):
    cfnConfig['packages'] = instance['Packages']

  resource = dict(
    Type = 'AWS::EC2::Instance',
    DependsOn = instance['DependsOn'],
    Metadata = {
      'AWS::CloudFormation::Init': dict(config = cfnConfig)
    },
    Properties = dict(
      ImageId = DemOS.InstancesAmi,
      InstanceType = instance['InstanceType'],
      IamInstanceProfile = {'Ref': instance['Profile']},
      KeyName = {'Fn::GetAtt': f'{DemOS.keyPair}.Name'},
      PropagateTagsToVolumeOnCreation = True,
      PrivateDnsNameOptions = dict(
        EnableResourceNameDnsARecord = False
      ),
      NetworkInterfaces = networkInterfaces,
      SourceDestCheck = True if instance['Label'] != 'Manager' else False,
      UserData = {
        'Fn::Base64': {
          'Fn::Sub': DemOS.j2('instances/user-data.yml', instance)
        }
      },
      Tags = [
        dict(
          Key = 'Name',
          Value = f'{DemOS.TagPrefix}-{instance["ResourceName"]}'
        )
      ]
    )
  )

  DemOS.resource(instance['ResourceName'], resource)

def make_route53_RecordSets(instance):
  for index in range(0, len(instance['Interfaces'])):
    subnet = instance['Interfaces'][index]
    public = DemOS.subnets[subnet]['Public']

    if index == 0:
      make_route53_RecordSet(dict(
        ResourceName = f'{instance["ResourceName"]}RecordSetPrivate{index}',
        DependsOn = instance['ResourceName'],
        Properties = dict(
          HostedZoneId = {'Ref': 'HostedZone'},
          Name = f'{instance["HostName"]}.{DemOS.PrivateDomain}.',
          ResourceRecords = [
            {'Fn::GetAtt': f'{instance["ResourceName"]}.PrivateIp'}
          ]
        )
      ))

      if public:
        if instance['Label'] == 'Manager':
          name = f'{DemOS.PublicDomain}.'
        else:
          name = f'{instance["HostName"]}.{DemOS.PublicDomain}.'

        make_route53_RecordSet(dict(
          ResourceName = f'{instance["ResourceName"]}RecordSetPublic{index}',
          DependsOn = instance['ResourceName'],
          Properties = dict(
            HostedZoneName = DemOS.HostedZoneName,
            Name = name,
            ResourceRecords = [
              {'Fn::GetAtt': f'{instance["ResourceName"]}.PublicIp'}
            ]
          )
        ))

    else:
      interface = f'{instance["ResourceName"]}Interface{index}'

      make_route53_RecordSet(dict(
        ResourceName = f'{instance["ResourceName"]}RecordSetPrivate{index}',
        DependsOn = interface,
        Properties = dict(
          HostedZoneId = {'Ref': 'HostedZone'},
          Name = f'{instance["HostName"]}-{index}.{DemOS.PrivateDomain}.',
          ResourceRecords = [
            {'Fn::GetAtt': f'{interface}.PrimaryPrivateIpAddress'}
          ]
        )
      ))

      if public:
        elasticIp = f'{instance["ResourceName"]}EIP{index}'

        make_route53_RecordSet(dict(
          ResourceName = f'{instance["ResourceName"]}RecordSetPublic{index}',
          DependsOn = elasticIp,
          Properties = dict(
            HostedZoneName = DemOS.HostedZoneName,
            Name = f'{instance["HostName"]}-{index}.{DemOS.PublicDomain}.',
            ResourceRecords = [
              {'Ref': elasticIp}
            ]
          )
        ))

def make_route53_RecordSet(record):
  resourceName = record['ResourceName']

  resource = dict(
    Type = 'AWS::Route53::RecordSet',
    Properties = dict(
      Type = 'A',
      TTL = 60
    ) | record['Properties']
  )

  if record.get('DependsOn'):
    resource['DependsOn'] = record['DependsOn']

  DemOS.resource(resourceName, resource)
