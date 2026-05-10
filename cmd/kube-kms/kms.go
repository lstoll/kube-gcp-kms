package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	kmsv2 "k8s.io/kms/apis/v2"
)

type kmsServer struct {
	kmsv2.UnimplementedKeyManagementServiceServer

	client *kms.KeyManagementClient
	keyID  string

	primaryKeyVersionID     string
	primaryKeyVersionExpiry time.Time
	primaryKeyVersionMu     sync.RWMutex
}

// getPrimaryKeyVersion returns the current primary CryptoKeyVersion resource name,
// using a short-lived cache to avoid a GCP API call on every Status request.
func (s *kmsServer) getPrimaryKeyVersion(ctx context.Context) (string, error) {
	if s.client == nil {
		return s.keyID, nil
	}

	s.primaryKeyVersionMu.RLock()
	id, expiry := s.primaryKeyVersionID, s.primaryKeyVersionExpiry
	s.primaryKeyVersionMu.RUnlock()

	if id != "" && time.Now().Before(expiry) {
		return id, nil
	}

	s.primaryKeyVersionMu.Lock()
	defer s.primaryKeyVersionMu.Unlock()
	if s.primaryKeyVersionID != "" && time.Now().Before(s.primaryKeyVersionExpiry) {
		return s.primaryKeyVersionID, nil
	}

	key, err := s.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: s.keyID})
	if err != nil {
		return "", fmt.Errorf("failed to get crypto key: %w", err)
	}
	if key.Primary == nil {
		return "", fmt.Errorf("crypto key %s has no primary version", s.keyID)
	}

	s.primaryKeyVersionID = key.Primary.Name
	s.primaryKeyVersionExpiry = time.Now().Add(5 * time.Minute)
	return s.primaryKeyVersionID, nil
}

func (s *kmsServer) Status(ctx context.Context, req *kmsv2.StatusRequest) (*kmsv2.StatusResponse, error) {
	slog.Debug("Handling Status request")
	keyVersionID, err := s.getPrimaryKeyVersion(ctx)
	if err != nil {
		slog.Error("Failed to get primary key version for Status", "error", err)
		return nil, err
	}
	return &kmsv2.StatusResponse{
		Version: "v2",
		Healthz: "ok",
		KeyId:   keyVersionID,
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

	// Update the primary version cache with what GCP actually used.
	s.primaryKeyVersionMu.Lock()
	s.primaryKeyVersionID = resp.Name
	s.primaryKeyVersionExpiry = time.Now().Add(5 * time.Minute)
	s.primaryKeyVersionMu.Unlock()

	return &kmsv2.EncryptResponse{
		Ciphertext: resp.Ciphertext,
		KeyId:      resp.Name,
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
