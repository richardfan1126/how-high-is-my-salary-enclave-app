#!/bin/bash

# Stop SSM agent - Fix issue: https://github.com/amazonlinux/amazon-linux-2023/issues/397
systemctl stop amazon-ssm-agent

# Install nitro-cli
dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y
systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now docker

# Start SSM agent
systemctl start amazon-ssm-agent

# Install Oras
cd /root
VERSION="1.1.0"
curl -LO "https://github.com/oras-project/oras/releases/download/v$${VERSION}/oras_$${VERSION}_linux_amd64.tar.gz"
mkdir -p /root/oras-install/
tar -zxf oras_$${VERSION}_*.tar.gz -C /root/oras-install/
mv /root/oras-install/oras /usr/local/bin/
rm -rf /root/oras_$${VERSION}_*.tar.gz /root/oras-install/

# Install socat
yum install socat -y

# Pull EIF
HOME=/root oras pull -o /root ${eifArtifactPath}

# Run socat
socat -t 30 TCP-LISTEN:80,fork,reuseaddr VSOCK-CONNECT:7777:1000 &

# Run enclave
nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-name test --enclave-cid 7777 --eif-path /root/enclave.eif
