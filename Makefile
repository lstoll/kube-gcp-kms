-include .env
export

GOARCH ?= arm64
BINARY  := kube-gcp-kms

BUILD_DATE := $(shell date -u +%Y%m%dT%H%M%S)
JJ_COMMIT  := $(shell jj log -r 'latest(::@ & ~empty())' --no-graph -T 'commit_id.short(8)' 2>/dev/null || git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
VERSION    := $(BUILD_DATE)-$(JJ_COMMIT)
LDFLAGS    := -ldflags "-X main.version=$(VERSION)"

.PHONY: build
build:
	GOOS=linux GOARCH=$(GOARCH) go build -o $(BINARY) ./cmd/kube-gcp-kms/

.PHONY: release
release:
	mkdir -p output
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o output/kube-gcp-kms_$(VERSION)_linux_amd64 ./cmd/kube-gcp-kms/
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o output/kube-gcp-kms_$(VERSION)_linux_arm64 ./cmd/kube-gcp-kms/
	cd output && sha256sum kube-gcp-kms_$(VERSION)_linux_amd64 > kube-gcp-kms_$(VERSION)_linux_amd64.sha256
	cd output && sha256sum kube-gcp-kms_$(VERSION)_linux_arm64 > kube-gcp-kms_$(VERSION)_linux_arm64.sha256
	@echo ""
	@echo "Version: $(VERSION)"
	@cat output/*.sha256

.PHONY: vagrant-up
vagrant-up: build
	vagrant up

.PHONY: vagrant-reprovision
vagrant-reprovision: build
	vagrant provision

.PHONY: vagrant-ssh
vagrant-ssh:
	vagrant ssh

.PHONY: test
test:
	go test ./...
