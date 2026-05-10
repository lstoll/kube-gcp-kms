-include .env
export

GOARCH ?= arm64
BINARY  := kube-kms

.PHONY: build
build:
	GOOS=linux GOARCH=$(GOARCH) go build -o $(BINARY) ./cmd/kube-kms/

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
