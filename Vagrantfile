Vagrant.configure("2") do |config|
  config.vm.box = "bento/ubuntu-24.04"

  # Assign some extra resources as k3s can be a bit heavy
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  config.vm.provision "shell", inline: <<-SHELL
    # Install k3s without traefik to save resources
    export INSTALL_K3S_EXEC="--disable traefik --write-kubeconfig-mode 644"
    curl -sfL https://get.k3s.io | sh -

    # Wait for node to be ready
    sleep 5
    kubectl wait --for=condition=Ready node --all --timeout=60s

    # Allow vagrant user to easily use kubectl
    mkdir -p /home/vagrant/.kube
    cp /etc/rancher/k3s/k3s.yaml /home/vagrant/.kube/config
    chown -R vagrant:vagrant /home/vagrant/.kube
  SHELL
end
