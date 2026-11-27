#!/usr/bin/env bash
# lab/azure/deploy.sh
# Deploys the single Windows Server 2025 VM used to generate telemetry for this project.
# Run from Azure Cloud Shell (Bash):  bash deploy.sh <your-public-ip>
# Get your public IP on your own machine, not in Cloud Shell:  curl -s https://api.ipify.org
set -euo pipefail

MY_IP="${1:?Usage: bash deploy.sh <your-public-ip>}"

RG="rg-wtdl"
RG_LOCATION="uksouth"          # where the resource group's metadata lives
VM_LOCATION="swedencentral"    # where capacity was available to a free trial (Nov 2026)
VM="wtdl-win01"
SIZE="Standard_D2as_v5"        # 2 vCPU, 8 GB. On SkuNotAvailable, try another size or region
ADMIN_USER="labadmin"          # Azure rejects 'admin' and 'administrator'
IMAGE="MicrosoftWindowsServer:WindowsServer:2025-datacenter-g2:latest"
SHUTDOWN_UTC="2200"            # daily auto-shutdown (deallocates), UTC

read -rs -p "VM admin password (12+ chars, 3 of: upper, lower, digit, symbol): " ADMIN_PASS; echo

az group create --name "$RG" --location "$RG_LOCATION" --output none

# --nsg-rule NONE: create the firewall with no inbound rules; RDP is opened to one IP below.
az vm create \
  --resource-group "$RG" --location "$VM_LOCATION" --name "$VM" \
  --image "$IMAGE" --size "$SIZE" \
  --admin-username "$ADMIN_USER" --admin-password "$ADMIN_PASS" \
  --storage-sku StandardSSD_LRS --public-ip-sku Standard \
  --nsg-rule NONE --tags project=wtdl --output table

unset ADMIN_PASS

az network nsg rule create \
  --resource-group "$RG" --nsg-name "${VM}NSG" --name Allow-RDP-MyIP \
  --priority 1000 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "$MY_IP" --destination-port-ranges 3389 --output table

# The schedule must be created in the VM's region, hence --location.
az vm auto-shutdown --resource-group "$RG" --name "$VM" \
  --location "$VM_LOCATION" --time "$SHUTDOWN_UTC" --output none

az vm show -d --resource-group "$RG" --name "$VM" \
  --query "{state:powerState, ip:publicIps, size:hardwareProfile.vmSize}" --output table
