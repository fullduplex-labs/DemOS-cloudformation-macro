#!/usr/bin/env bash
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
set -e

export PATH="/usr/sbin:$PATH"

# Environment Variables: Common
Version="$Version"
AwsRegion="$AwsRegion"
AccessPoint="$AccessPoint"
FileSystem="$FileSystem"
InstanceLogGroup="$InstanceLogGroup"
ServicesLogGroup="$ServicesLogGroup"
AwsRegistry="$AwsRegistry"
InstanceType="$InstanceType"
InstanceLabel="$InstanceLabel"
InstanceName="$InstanceName"

# Environment Variables: Manager
CertificatePackage="$CertificatePackage"
SubnetOpsCidr="$SubnetOpsCidr"
SubnetPrivateCidr="$SubnetPrivateCidr"

# Utility Variables
ProjectRoot="/opt/demos"
EfsRoot="/mnt/efs"
ProjectGlobals="/etc/profile.d/globals.sh"
DockerCompose="https://github.com/docker/compose/releases/download/v2.16.0/docker-compose-linux-aarch64"

# Save Globals
################################################################################
cat <<EOF >> $ProjectGlobals
export Version="$Version"
export AwsRegion="$AwsRegion"
export AwsRegistry="$AwsRegistry"
export InstanceType="$InstanceType"
export InstanceLabel="$InstanceLabel"
export InstanceName="$InstanceName"
export ProjectRoot="$ProjectRoot"
export EfsRoot="$EfsRoot"
EOF

# Helpers
################################################################################
function prepareInstance() {
  printf "\nunset HISTFILE\nexport LESSHISTFILE=/dev/null\n" >> /root/.bashrc
  su ec2-user -c 'printf "\nunset HISTFILE\nexport LESSHISTFILE=/dev/null\n" \
    >> /home/ec2-user/.bashrc'

  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  systemctl restart sshd

  chown -R root:root $ProjectRoot

  mkdir -p $EfsRoot
  mount -t efs -o tls,accesspoint=$AccessPoint $FileSystem:/ $EfsRoot

  return
}

function configureDocker () {
  usermod -aG docker ec2-user

  printf '
  {
    "log-driver": "awslogs",
    "log-opts": {
      "awslogs-region": "%s",
      "awslogs-group": "%s",
      "tag": "%s/{{.Name}}/{{.ID}}"
    },
    "labels": [
      "aws.region=%s",
      "instance.type=%s",
      "instance.label=%s",
      "instance.name=%s"
    ]
  }' \
    "$AwsRegion" \
    "$ServicesLogGroup" \
    "${InstanceName#Instance*}" \
    "$AwsRegion" \
    "$InstanceType" \
    "$InstanceLabel" \
    "${InstanceName#Instance*}" \
  > /etc/docker/daemon.json

  mkdir -p /root/.docker /home/ec2-user/.docker
  printf '
  {
    "credHelpers": {
      "public.ecr.aws": "ecr-login",
      "%s": "ecr-login"
    }
  }' \
    "${AwsRegistry%%/*}" \
  | tee /root/.docker/config.json > /home/ec2-user/.docker/config.json

  systemctl enable docker
  systemctl restart docker || systemctl start docker

  dockerPlugins="/usr/libexec/docker/cli-plugins"
  mkdir -p $dockerPlugins
  wget -O $dockerPlugins/docker-compose "$DockerCompose" || {
    echo "Unable to install docker-compose"
    return 0
  }
  chmod +x $dockerPlugins/docker-compose

  return
}

function initializeManager() {
  declare \
    file="${CertificatePackage##*/}"

  aws --region "$AwsRegion" s3 cp "$CertificatePackage" "$EfsRoot/$file"
  tar --directory "$EfsRoot" -xzf "$EfsRoot/$file"
  rm "$EfsRoot/$file"
  chmod 600 \
    $EfsRoot/${file%.*}/*/key.pem \
    $EfsRoot/${file%.*}/*/private.pem

  cp $EfsRoot/${file%.*}/authority/cert.pem \
    /etc/pki/ca-trust/source/anchors/private-ca.crt
  update-ca-trust force-enable
  update-ca-trust extract

  sysctl -qw net.ipv4.conf.eth0.forwarding=1
  sysctl -qw net.ipv4.conf.eth0.send_redirects=0

  iptables -w -I DOCKER-USER -i eth0 -o eth0 -j ACCEPT

  iptables -w -t nat \
    -A POSTROUTING -s "$SubnetOpsCidr" -o eth0 -j MASQUERADE
  iptables -w -t nat \
    -A POSTROUTING -s "$SubnetPrivateCidr" -o eth0 -j MASQUERADE

  return
}

# Run
################################################################################
prepareInstance
configureDocker

if [[ $InstanceType == 'manager' ]]; then
  initializeManager
fi

exit