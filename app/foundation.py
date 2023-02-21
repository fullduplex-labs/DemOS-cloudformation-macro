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
import re
import _globals as DemOS

def make():
  make_ecs_Cluster()
  make_ec2_VPC()
  make_route53_HostedZone()
  make_ec2_DHCPOptions()
  make_ec2_InternetGateway()
  make_efs_FileSystem()
  make_Certificates()
  make_logs_LogGroups()

  if DemOS.State == 'On':
    make_ec2_Subnets()
    make_ec2_SecurityGroups()
    make_efs_MountTarget()

def make_ecs_Cluster():
  DemOS.resource('Cluster', dict(
    Type = 'AWS::ECS::Cluster',
    Properties = dict(
      ClusterName = DemOS.ClusterEcs,
      ClusterSettings = [
        dict(
          Name = 'containerInsights',
          Value = 'disabled'
        )
      ],
      Tags = [
        dict(Key = 'Name', Value = DemOS.TagPrefix)
      ]
    )
  ))

def make_ec2_VPC():
  DemOS.resource('Vpc', dict(
    Type = 'AWS::EC2::VPC',
    Properties = dict(
      CidrBlock = DemOS.Subnets['Private'],
      EnableDnsSupport = True,
      EnableDnsHostnames = True,
      Tags = [dict(Key = 'Name', Value = DemOS.TagPrefix)]
    )
  ))

  for subnet in DemOS.Subnets.keys():
    if subnet in ['Private', 'Vpn']: continue

    DemOS.resource(f'VpcCidrBlock{subnet}', dict(
      Type = 'AWS::EC2::VPCCidrBlock',
      DependsOn = 'Vpc',
      Properties = dict(
        VpcId = {'Ref': 'Vpc'},
        CidrBlock = DemOS.Subnets[subnet]
      )
    ))

  DemOS.resource('VpcCidrBlockIpv6', dict(
    Type = 'AWS::EC2::VPCCidrBlock',
    DependsOn = 'Vpc',
    Properties = dict(
      VpcId = {'Ref': 'Vpc'},
      AmazonProvidedIpv6CidrBlock = True
    )
  ))

def make_route53_HostedZone():
  DemOS.resource('HostedZone', dict(
    Type = 'AWS::Route53::HostedZone',
    DependsOn = 'Vpc',
    Properties = dict(
      Name = DemOS.PrivateDomain,
      VPCs = [
        dict(
          VPCId = {'Ref': 'Vpc'},
          VPCRegion = DemOS.Region
        )
      ],
      HostedZoneConfig = dict(
        Comment = DemOS.Name
      )
    )
  ))

def make_ec2_DHCPOptions():
  DemOS.resource('VpcDhcpOptions', dict(
    Type = 'AWS::EC2::DHCPOptions',
    Properties = dict(
      DomainName = DemOS.PrivateDomain,
      DomainNameServers = [ '169.254.169.253' ],
      NtpServers = [ '169.254.169.123' ],
      Tags = [
        dict(Key = 'Name', Value = DemOS.TagPrefix)
      ]
    )
  ))

  DemOS.resource('VpcDhcpOptionsAssociation', dict(
    Type = 'AWS::EC2::VPCDHCPOptionsAssociation',
    DependsOn = [
      'Vpc',
      'VpcDhcpOptions'
    ],
    Properties = dict(
      VpcId = {'Ref': 'Vpc'},
      DhcpOptionsId = {'Ref': 'VpcDhcpOptions'}
    )
  ))

def make_ec2_InternetGateway():
  DemOS.resource('GatewayInternet', dict(
    Type = 'AWS::EC2::InternetGateway',
    Properties = dict(
      Tags = [
        dict(Key = 'Name', Value = DemOS.TagPrefix)
      ]
    )
  ))

  DemOS.resource('GatewayInternetAttachment', dict(
    Type = 'AWS::EC2::VPCGatewayAttachment',
    DependsOn = ['Vpc', 'GatewayInternet', 'VpcCidrBlockIpv6'],
    Properties = dict(
      InternetGatewayId = {'Ref': 'GatewayInternet'},
      VpcId = {'Ref': 'Vpc'}
    )
  ))

  DemOS.resource('GatewayInternetV6', dict(
    Type = 'AWS::EC2::EgressOnlyInternetGateway',
    DependsOn = ['Vpc', 'VpcCidrBlockIpv6'],
    Properties = dict(
      VpcId = {'Ref': 'Vpc'}
    )
  ))

def make_ec2_Subnets():
  make_ec2_Subnet(dict(
    Scope = 'Portal',
    Label = 'portal',
    Count = 1,
    Start = 1,
    Public = True
  ))

  make_ec2_Subnet(dict(
    Scope = 'Ops',
    Label = 'ops',
    Count = 4,
    Start = 1,
    Public = False
  ))

  make_ec2_Subnet(dict(
    Scope = 'Private',
    Label = 'soc',
    Count = 1,
    Start = 1,
    Public = False
  ))

  make_ec2_Subnet(dict(
    Scope = 'Private',
    Label = 'servers',
    Count = 1,
    Start = 100,
    Public = False
  ))

  make_ec2_Subnet(dict(
    Scope = 'Private',
    Label = 'users',
    Count = 1,
    Start = 200,
    Public = False
  ))

  make_ec2_Subnet(dict(
    Scope = 'Public',
    Label = 'dmz',
    Count = 1,
    Start = 1,
    Public = True
  ))

  make_ec2_Subnet(dict(
    Scope = 'Public',
    Label = 'pub',
    Count = 1,
    Start = 100,
    Public = True
  ))

def make_ec2_Subnet(subnet):

  dependsOn = ['Vpc', 'VpcCidrBlockIpv6']
  if subnet['Scope'] != 'Private':
    dependsOn.append(f'VpcCidrBlock{subnet["Scope"]}')

  scopeCidr = DemOS.Subnets[subnet['Scope']]
  scopePrefix = re.search(r'^([0-9]+\.[0-9]+)\.', scopeCidr).group(1)

  subnet['Names'] = []
  subnet['Associations'] = []
  subnetStart = subnet['Start']

  make_ec2_RouteTable(subnet)

  for i in range(1, subnet['Count'] + 1):
    for zone in DemOS.RegionVpcSubnetZones:

      subnetCidr = f'{scopePrefix}.{subnetStart}.0/24'
      subnetStart += 1

      resourceName = f'Subnet{subnet["Label"].title()}{i}{zone}'
      subnet['Names'].append(resourceName)

      ipv6Block = DemOS.subnetsCount
      DemOS.subnetsCount += 1

      DemOS.resource(resourceName, dict(
        Type = 'AWS::EC2::Subnet',
        DependsOn = dependsOn,
        Properties = dict(
          VpcId = {'Ref': 'Vpc'},
          AvailabilityZone = f'{DemOS.Region}{zone}',
          CidrBlock = subnetCidr,
          MapPublicIpOnLaunch = subnet['Public'],
          AssignIpv6AddressOnCreation = True,
          PrivateDnsNameOptionsOnLaunch = dict(
            HostnameType = 'resource-name',
            EnableResourceNameDnsARecord = True,
            EnableResourceNameDnsAAAARecord = True
          ),
          Ipv6CidrBlock = {
            'Fn::Select': [
              ipv6Block,
              {
                'Fn::Cidr': [
                  {'Fn::Select': [ 0, {'Fn::GetAtt': 'Vpc.Ipv6CidrBlocks'}]},
                  ipv6Block + 1,
                  64
                ]
              }
            ]
          },
          Tags = [
            dict(
              Key = 'Name',
              Value = f'{DemOS.TagPrefix}-{subnet["Label"]}-{i}{zone}'
            )
          ]
        )
      ))

      association = f'RouteTableAssociation{resourceName}'
      subnet['Associations'].append(association)

      DemOS.resource(association, dict(
        Type = 'AWS::EC2::SubnetRouteTableAssociation',
        DependsOn = [resourceName, subnet['RouteTable']],
        Properties = dict(
          RouteTableId = {'Ref': subnet['RouteTable']},
          SubnetId = {'Ref': resourceName}
        )
      ))

  if subnet['Public']:
    make_ec2_Route(subnet, dict(Default = True, IpVersion = 4))

  make_ec2_Route(subnet, dict(Default = True, IpVersion = 6))

  DemOS.subnets[subnet['Label']] = subnet

def make_ec2_RouteTable(subnet):
  resourceName = f'RouteTable{subnet["Scope"].title()}'
  subnet['RouteTable'] = resourceName

  if DemOS.routeTables.get(subnet['Scope']) is None:
    DemOS.routeTables[subnet['Scope']] = resourceName
  else: return

  DemOS.resource(resourceName, dict(
    Type = 'AWS::EC2::RouteTable',
    DependsOn = 'Vpc',
    Properties = dict(
      VpcId = {'Ref': 'Vpc'},
      Tags = [
        dict(
          Key = 'Name',
          Value = f'{DemOS.TagPrefix}-{subnet["Scope"]}'
        )
      ]
    )
  ))

def make_ec2_Route(subnet, route):
  label = 'Default' if route.get('Default') else route['Label']
  ipVersion = route.get('IpVersion', 4)

  resourceName = f'{subnet["RouteTable"]}{label}Ip{ipVersion}'

  resource = dict(
    Type = 'AWS::EC2::Route',
    DependsOn = route.get('DependsOn', []) + [subnet['RouteTable']],
    Properties = route.get('Properties', {}) | dict(
      RouteTableId = {'Ref': subnet['RouteTable']}
    )
  )

  if route.get('Default'):

    if not subnet.get('DefaultRoutes'):
      subnet['DefaultRoutes'] = [resourceName]

    elif resourceName not in subnet['DefaultRoutes']:
      subnet['DefaultRoutes'].append(resourceName)

    if ipVersion == 4:
      resource['Properties']['DestinationCidrBlock'] = '0.0.0.0/0'

      if subnet['Public']:
        gateway = 'GatewayInternet'
        resource['Properties']['GatewayId'] = {'Ref': gateway}

      elif route.get('Instance'):
        gateway = route['Instance']
        resource['Properties']['InstanceId'] = {'Ref': gateway}

    else:
      resource['Properties']['DestinationIpv6CidrBlock'] = '::/0'

      gateway = 'GatewayInternetV6'
      resource['Properties']['EgressOnlyInternetGatewayId'] = {'Ref': gateway}

    resource['DependsOn'] += [gateway, 'GatewayInternetAttachment']
    resource['DependsOn'] += subnet['Associations']

  DemOS.resource(resourceName, resource, overwrite=True)

def make_ec2_SecurityGroups():
  make_ec2_SecurityGroup('Sudo', ingress=[
    dict(
      Description = 'Portainer',
      IpProtocol = 'tcp',
      FromPort = 9443,
      ToPort = 9443,
      CidrIp = DemOS.GlobalOpsCidrs
    ),
    dict(
      Description = 'Console',
      IpProtocol = 'tcp',
      FromPort = 22,
      ToPort = 22,
      CidrIp = DemOS.GlobalOpsCidrs
    ),
    dict(
      Description = 'VPN',
      IpProtocol = 'udp',
      FromPort = 1194,
      ToPort = 1194,
      CidrIp = ['0.0.0.0/0']
    )
  ])

  make_ec2_SecurityGroup('Local', ingress=[
    dict(
      Description = 'Local',
      IpProtocol = -1,
      CidrIp = [
        DemOS.Subnets['Portal'],
        DemOS.Subnets['Ops'],
        DemOS.Subnets['Public'],
        DemOS.Subnets['Private'],
        DemOS.Subnets['Vpn']
      ]
    )
  ])

def make_efs_FileSystem():
  DemOS.resource('FileSystem', dict(
    Type = 'AWS::EFS::FileSystem',
    DeletionPolicy = 'Delete',
    Properties = dict(
      Encrypted = True,
      BackupPolicy = dict(Status = 'ENABLED'),
      FileSystemTags = [
        dict(Key = 'Name', Value = DemOS.TagPrefix)
      ]
    )
  ))

  DemOS.resource('AccessPoint', dict(
    Type = 'AWS::EFS::AccessPoint',
    DependsOn = 'FileSystem',
    Properties = dict(
      FileSystemId = {'Ref': 'FileSystem'},
      PosixUser = dict(Uid = 1000, Gid = 1000),
      RootDirectory = dict(
        Path = '/clusterfs',
        CreationInfo = dict(
          OwnerGid = 1000,
          OwnerUid = 1000,
          Permissions = 755
        )
      ),
      AccessPointTags = [
        dict(Key = 'Name', Value = DemOS.TagPrefix)
      ]
    )
  ))

def make_efs_MountTarget():
    DemOS.resource('MountTarget', dict(
      Type = 'AWS::EFS::MountTarget',
      DependsOn = [
        'FileSystem',
        'SecurityGroupLocal'
      ],
      Properties = dict(
        FileSystemId = {'Ref': 'FileSystem'},
        SecurityGroups = [
          {'Ref': 'SecurityGroupLocal'}
        ],
        SubnetId = {'Ref': DemOS.subnets['servers']['Names'][0]}
      )
    ))

def make_Certificates():
  certificates = [
    'Authority',
    'Internal',
    'External',
    'DiffieHellman',
    'SSH',
    'Public',
    'VpnGateway'
  ]

  properties = dict(
    ServiceToken = DemOS.CertificateAuthority,
    Name = DemOS.Name,
    Label = DemOS.Label
  )

  for cert in certificates:
    resourceName = f'Certificate{cert}'

    resource = dict(
      Type = f'Custom::{resourceName}',
      Properties = properties
    )

    if cert in ['Internal', 'External']:
      resource['DependsOn'] = DemOS.certificates['Authority']
    elif cert == 'VpnGateway':
      resource['DependsOn'] = [
        DemOS.certificates['Authority'],
        DemOS.certificates['Internal']
      ]

    DemOS.resource(resourceName, resource)
    DemOS.certificates[cert] = resourceName

  resourceName = 'CertificatePackage'
  DemOS.resource(resourceName, dict(
    Type = f'Custom::{resourceName}',
    DependsOn = list(DemOS.certificates.values()),
    Properties = properties
  ))
  DemOS.certificatePackage = resourceName

def make_ec2_SecurityGroup(label, ingress=[]):

  ingressRules = []
  for rule in ingress:
    if rule.get('CidrIp'):
      cidrs = rule.pop('CidrIp')
      for cidr in cidrs:
        ingressRules.append(rule | dict(CidrIp = cidr))
    elif rule.get('CidrIpv6'):
      cidrs = rule.pop('CidrIpv6')
      for cidr in cidrs:
        ingressRules.append(rule | dict(CidrIpv6 = cidr))
    elif rule.get('SourceSecurityGroupId'):
      groups = rule.pop('SourceSecurityGroupId')
      for group in groups:
        ingressRules.append(rule | dict(SourceSecurityGroupId = group))
    elif rule.get('SourceSecurityGroupName'):
      groups = rule.pop('SourceSecurityGroupName')
      for group in groups:
        ingressRules.append(rule | dict(SourceSecurityGroupName = group))

  groupName = f'{DemOS.Namespace}-{DemOS.Project}-{DemOS.Name}.{label}'
  DemOS.resource(f'SecurityGroup{label}', dict(
    Type = 'AWS::EC2::SecurityGroup',
    Properties = dict(
      GroupName = groupName,
      GroupDescription = groupName,
      VpcId = {'Ref': 'Vpc'},
      SecurityGroupIngress = ingressRules,
      Tags = [
        dict(
          Key = 'Name',
          Value = f'{DemOS.TagPrefix}.{label}'
        )
      ]
    )
  ))

def make_logs_LogGroups():
  for group in DemOS.Logs:
    for log in DemOS.Logs[group]:
      DemOS.resource(f'Logs{group}{log}', dict(
        Type = 'AWS::Logs::LogGroup',
        Properties = dict(
          RetentionInDays = 7,
          LogGroupName = DemOS.Logs[group][log]['Name']
        )
      ))
