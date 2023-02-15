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
import logging, os, json, re, types, base64
import boto3, jinja2

_logger = logging.getLogger()
if os.environ.get('LOG_LEVEL') == 'DEBUG':
  _logger.setLevel(logging.DEBUG)
else:
  _logger.setLevel(logging.INFO)
  logging.disable(logging.DEBUG)

# Globals: Namespace
Version = os.environ['Version']
Namespace = os.environ['Namespace']
Project = os.environ['Project']
Domain = os.environ['Domain']
KeyAlias = os.environ['KeyAlias']
CertificateAuthority = os.environ['CertificateAuthority']
SecretProvider = os.environ['SecretProvider']
HostedZoneId = os.environ['HostedZoneId']
HostedZoneName = os.environ['HostedZoneName']
ProductName = os.environ['ProductName']
GlobalOpsCidrs = json.loads(os.environ['GlobalOpsCidrs'])
Subnets = json.loads(os.environ['Subnets'])
Workers = json.loads(os.environ['Workers'])
InstancesAmi = os.environ['InstancesAmi']
RegionVpcSubnetZones = ['a', 'b']

# Globals: provided by CloudFormation macro invocation
AccountId = None
Region = None
StackId = None
StackName = None
ProductVersion = None
State = None
Fragment = None

# Globals: computed
Name = None
TagPrefix = None
PrivateDomain = None
PublicDomain = None
Stack = None
Label = None
User = None
ClusterEcs = None
ClusterEcsArn = None
ClusterEcsInstanceArn = None
RegistryEcr = None
RegistryEcrArn = None
Logs = None

# Globals: utilities
subnets = {}
subnetsCount = 0
routeTables = {}
keyPair = None
secrets = {}
certificates = {}
certificatePackage = None
certificatePath = '/mnt/efs/certificates'

# CloudFormation template response
_resources = {}
_outputs = {}

def init(event):
  global AccountId, Region, StackId, StackName, ProductVersion, State
  global Fragment, Name, TagPrefix, PrivateDomain, PublicDomain
  global ClusterEcs, ClusterEcsArn, ClusterEcsInstanceArn, RegistryEcr
  global RegistryEcrArn, Logs

  log(json.dumps(event))

  AccountId = event['accountId']
  Region = event['region']
  StackId = event['params']['StackId']
  StackName = event['params']['StackName']
  ProductVersion = event['params']['ProductVersion']
  State = event['templateParameterValues']['State']
  Fragment = event['fragment']

  Name = re.sub(r'^.+-pp-', '', StackName)

  TagPrefix = f'{Namespace}-{Project}-{Name}'
  PrivateDomain = f'i.{Domain}'
  PublicDomain = f'{Name}.{Region}.{Domain}'.lower()

  ClusterEcs = f'{Namespace}-{Project}-{Name}'
  ClusterEcsArn = f'arn:aws:ecs:{Region}:{AccountId}:cluster/{ClusterEcs}'
  ClusterEcsInstanceArn = f'arn:aws:ecs:{Region}:{AccountId}:container-instance'
  ClusterEcsInstanceArn += f'/{ClusterEcs}'

  RegistryEcr = f'{AccountId}.dkr.ecr.{Region}.amazonaws.com/{Namespace}'
  RegistryEcrArn = f'arn:aws:ecr:{Region}:{AccountId}:repository/{Namespace}'

  logPrefix = f'/{Namespace}/{Project}/{Name}'.lower()
  logPrefixArn = f'arn:aws:logs:{Region}:{AccountId}:log-group:{logPrefix}'
  Logs = dict(
    Services = dict(
      Instances = dict(
        Name = f'{logPrefix}/services/instances',
        Arn = f'{logPrefixArn}/services/instances'
      ),
      Ecs = dict(
        Name = f'{logPrefix}/services/ecs',
        Arn = f'{logPrefixArn}/services/ecs'
      )
    )
  )

  __get_Stack()

def resource(name, resource, overwrite=False):
  global _resources

  if overwrite is not True and _resources.get(name):
    raise Exception(f'A resource with name:[{name}] already exists')

  _resources[name] = resource

def output(key, value, state):
  global _outputs

  if state.title() in [State, 'All']:
    _outputs[key] = dict(
      Value = value
    )

def template():
  return Fragment | dict(
    Description = f'{ProductName} v{Version} ({State})',
    Resources = _resources,
    Outputs = _outputs
  )

def deepCopy(src):
  try:
    return json.loads(json.dumps(src))
  except:
    from copy import deepcopy
    return deepcopy(src)

def include(includeFile, b64=False):
  with open(f'includes/{includeFile}', 'r') as f:
    _file = f.read()

  if b64: _file = base64.b64encode(_file.encode())

  return _file

def j2(templateFile, data=None, b64=False):
  _template = jinja2.Environment(
    loader = jinja2.FileSystemLoader(searchpath='templates/')
  ).get_template(templateFile)

  _g = {}
  for var,val in globals().items():
    if re.match('_', var) or callable(val) or type(val) is types.ModuleType:
      continue
    _g[var] = val

  _context = {
    'DemOS': _g,
    'data': data or {}
  }

  _rendered = _template.render(_context)

  if b64: _rendered = base64.b64encode(_rendered.encode())

  return _rendered

def log(message, debug=False, exception=False):
  if debug:
    _logger.debug(message)
  elif exception:
    _logger.exception(message)
  else:
    _logger.info(message)

def __get_Stack():
  global Stack, Label, User

  client = boto3.client('cloudformation')
  response = client.describe_stacks(
    StackName = StackId
  )

  Stack = response['Stacks'][0]
  Stack['Tags'] = {k:v for t in Stack['Tags'] for k,v in [t.values()]}

  tag = 'aws:servicecatalog:provisionedProductArn'
  Label = Stack['Tags'][tag]
  Label = Label.split('/')[1]

  tag = 'aws:servicecatalog:provisioningPrincipalArn'
  User = Stack['Tags'][tag]
