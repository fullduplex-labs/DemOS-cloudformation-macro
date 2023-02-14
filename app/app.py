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
import foundation, instances, services

"""
event:
  region: "$REGION",
  accountId: "$ACCOUNT_ID",
  fragment: { ... },
  transformId: "$TRANSFORM_ID",
  params: { ... },
  requestId: "$REQUEST_ID",
  templateParameterValues: { ... }

context:
  aws_request_id: "$REQUEST_ID"
  log_group_name: "/aws/lambda/$FUNCTION_NAME"
  log_stream_name: "YYYY/MM/DD/[$LATEST]$CONTAINER_ID"
  function_name: "$FUNCTION_NAME"
  memory_limit_in_mb: 128
  function_version: "$LATEST"
  invoked_function_arn: "$FUNCTION_ARN"
  client_context: None
  identity:
    cognito_identity_id: None
    cognito_identity_pool_id: None

response:
  requestId: "$REQUEST_ID",
  status: "$STATUS",
  fragment: { ... },
  [ 
    errorMessage: "$ERROR_MESSAGE"
  ]
"""
def handler(event, context):
  try:
    DemOS.init(event)

    foundation.make()
    instances.make()
    services.make()

    response = {
      "requestId" : event['requestId'],
      "status" : "success",
      "fragment" : DemOS.template()
    }

  except Exception as e:
    DemOS.log(e, exception=True)
    response = {
      "requestId" : event['requestId'],
      "status" : "error",
      "errorMessage" : str(e)
    }

  return response