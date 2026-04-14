#!/usr/bin/env bash
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (e.g., sudo ./configure-k3s.sh)"
  exit 1
fi

echo "Configuring k3s with custom API server arguments..."

# Create the k3s config directory if it doesn't exist
mkdir -p /etc/rancher/k3s

# Write the encryption provider config
cat <<EOF > /etc/rancher/k3s/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - kms:
          name: gcp-kms-plugin
          endpoint: unix:///var/run/kmsplugin/socket.sock
          apiVersion: v2
      - identity: {} # fallback option.
EOF
chmod 600 /etc/rancher/k3s/encryption-config.yaml

# Write the config file for k3s
cat <<EOF > /etc/rancher/k3s/config.yaml
kube-apiserver-arg:
  - "encryption-provider-config=/etc/rancher/k3s/encryption-config.yaml"
  - "service-account-signing-endpoint=/var/run/jwtplugin/socket.sock"
  - "service-account-signing-key-file="
  - "service-account-key-file="
EOF

echo "Restarting k3s to apply changes..."
systemctl restart k3s

echo "Waiting for k3s to come back up..."
sleep 5
kubectl wait --for=condition=Ready node --all --timeout=60s || true

echo "Done! k3s is now configured to use the external KMS and JWT plugins."
echo "Note: The plugins must be running and listening on their sockets before the API server can successfully process requests."
