# kube-kms

Kubernetes KMS v2 encryption provider and External JWT signer plugin backed by GCP Cloud KMS. Runs as a single binary exposing two Unix-socket gRPC servers for use with k3s (or any kube-apiserver that supports these interfaces).

## Testing with Vagrant

Prerequisites: VirtualBox, Vagrant, a GCP project with:
- A symmetric encryption key (AES-256-GCM) for KMS
- An asymmetric signing key (EC P-256) for JWT signing
- A service account key JSON with `roles/cloudkms.cryptoKeyEncrypterDecrypter` and `roles/cloudkms.signerVerifier`

**1. Configure your environment:**

```sh
cp .env.example .env
# edit .env with your GCP resource names, SA key path, and k3s binary path
```

If you use [direnv](https://direnv.net/), run `direnv allow` and the vars will be exported automatically. Otherwise the Makefile loads `.env` directly.

**2. Build a patched k3s** (required — vanilla k3s doesn't support `--service-account-signing-endpoint`; see `k3s-args-patch.diff`). Set `K3S_BINARY` in `.env` to point at it.

**3. Bring up the VM:**

```sh
make vagrant-up
```

This builds the Linux binary then runs `vagrant up`. Provisioning installs k3s, starts `kube-kms` as a systemd service, and runs `configure-k3s.sh` to wire the API server to both plugins.

**4. Verify:**

```sh
make vagrant-ssh
kubectl create -f /vagrant/test-manifests/secret.yaml
kubectl get secret test-kms-secret -o yaml  # ciphertext visible in etcd
```

To iterate on the binary: run `make vagrant-reprovision` (rebuilds and re-runs provisioning), or for a faster loop just rebuild and restart the service inside the VM:

```sh
make build && vagrant ssh -c 'sudo systemctl restart kube-kms'
```
