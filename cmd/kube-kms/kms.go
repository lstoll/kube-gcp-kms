package main

import (
	"context"
	"fmt"
	"log/slog"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	kmsv2 "k8s.io/kms/apis/v2"
)

type kmsServer struct {
	kmsv2.UnimplementedKeyManagementServiceServer

	client *kms.KeyManagementClient
	keyID  string
}

func (s *kmsServer) Status(ctx context.Context, req *kmsv2.StatusRequest) (*kmsv2.StatusResponse, error) {
	slog.Info("Handling Status request")
	return &kmsv2.StatusResponse{
		Version: "v2",
		Healthz: "ok",
		KeyId:   s.keyID,
	}, nil
}

func (s *kmsServer) Encrypt(ctx context.Context, req *kmsv2.EncryptRequest) (*kmsv2.EncryptResponse, error) {
	slog.Info("Handling Encrypt request", "uid", req.Uid, "keyID", s.keyID)
	resp, err := s.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      s.keyID,
		Plaintext: req.Plaintext,
	})
	if err != nil {
		slog.Error("Encrypt failed", "uid", req.Uid, "error", err)
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return &kmsv2.EncryptResponse{
		Ciphertext: resp.Ciphertext,
		KeyId:      s.keyID,
	}, nil
}

func (s *kmsServer) Decrypt(ctx context.Context, req *kmsv2.DecryptRequest) (*kmsv2.DecryptResponse, error) {
	slog.Info("Handling Decrypt request", "uid", req.Uid, "keyID", s.keyID)
	resp, err := s.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       s.keyID,
		Ciphertext: req.Ciphertext,
	})
	if err != nil {
		slog.Error("Decrypt failed", "uid", req.Uid, "error", err)
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return &kmsv2.DecryptResponse{
		Plaintext: resp.Plaintext,
	}, nil
}
