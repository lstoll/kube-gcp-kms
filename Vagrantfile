Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"

  # Assign some extra resources as k3s can be a bit heavy
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  # Required: GCP resource names
  #   GCP_KMS_KEY=projects/p/locations/l/keyRings/r/cryptoKeys/k
  #   GCP_JWT_KEY=projects/p/locations/l/keyRings/r/cryptoKeys/k   (key name, not a specific version)
  # Required: GCP service account key JSON path (host path)
  #   GOOGLE_SA_KEY=/path/to/sa-key.json
  # Optional: custom (patched) k3s binary (see k3s-args-patch.diff)
  #   K3S_BINARY=/path/to/k3s
  k3s_binary    = ENV["K3S_BINARY"]
  gcp_kms_key   = ENV["GCP_KMS_KEY"]  or abort "GCP_KMS_KEY must be set"
  gcp_jwt_key   = ENV["GCP_JWT_KEY"]  or abort "GCP_JWT_KEY must be set"
  google_sa_key = ENV["GOOGLE_SA_KEY"] or abort "GOOGLE_SA_KEY must be set"

  if k3s_binary
    config.vm.provision "file", source: k3s_binary, destination: "/tmp/k3s-custom"
  end

  config.vm.provision "file", source: google_sa_key, destination: "/tmp/sa-key.json"

  config.vm.provision "shell", inline: <<-SHELL
    export INSTALL_K3S_EXEC="--disable traefik --write-kubeconfig-mode 644"

    if [ -f /tmp/k3s-custom ]; then
      echo "Using custom k3s binary..."
      install -m 0755 /tmp/k3s-custom /usr/local/bin/k3s
      export INSTALL_K3S_SKIP_DOWNLOAD=true
    fi

    curl -sfL https://get.k3s.io | sh -

    # Wait for node to be ready
    sleep 5
    kubectl wait --for=condition=Ready node --all --timeout=60s

    # Allow vagrant user to easily use kubectl
    mkdir -p /home/vagrant/.kube
    cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config
    chown -R vagrant:vagrant /home/vagrant/.kube

    # Install GCP service account key
    install -m 0600 /tmp/sa-key.json /etc/kube-gcp-kms-sa-key.json
    rm /tmp/sa-key.json

    # Create Unix socket directories for the plugins
    mkdir -p /var/run/kmsplugin /var/run/jwtplugin

    # Install kube-gcp-kms systemd service
    cat <<EOF > /etc/systemd/system/kube-gcp-kms.service
[Unit]
Description=kube-gcp-kms GCP KMS + JWT signer plugin
After=network.target
Before=k3s.service

[Service]
ExecStart=/vagrant/kube-gcp-kms \\
  --gcp-kms-key=#{gcp_kms_key} \\
  --gcp-jwt-key=#{gcp_jwt_key}
Environment=GOOGLE_APPLICATION_CREDENTIALS=/etc/kube-gcp-kms-sa-key.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable kube-gcp-kms
    systemctl start kube-gcp-kms

    # Configure k3s to use the plugins
    /vagrant/configure-k3s.sh
  SHELL
end
