package main

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/timestamppb"
	jwtsignerv1 "k8s.io/externaljwt/apis/v1"
)

type externalJWTServer struct {
	jwtsignerv1.UnimplementedExternalJWTSignerServer

	client       *kms.KeyManagementClient
	keyVersionID string

	fetchResp   *jwtsignerv1.FetchKeysResponse
	fetchRespMu sync.Mutex
}

func (s *externalJWTServer) Metadata(ctx context.Context, req *jwtsignerv1.MetadataRequest) (*jwtsignerv1.MetadataResponse, error) {
	slog.Info("Handling Metadata request")
	return &jwtsignerv1.MetadataResponse{
		MaxTokenExpirationSeconds: int64((6 * time.Hour).Seconds()),
	}, nil
}

func (s *externalJWTServer) FetchKeys(ctx context.Context, req *jwtsignerv1.FetchKeysRequest) (*jwtsignerv1.FetchKeysResponse, error) {
	slog.Info("Handling FetchKeys request", "keyVersionID", s.keyVersionID)

	s.fetchRespMu.Lock()
	defer s.fetchRespMu.Unlock()

	if s.fetchResp != nil {
		return s.fetchResp, nil
	}

	pk, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: s.keyVersionID,
	})
	if err != nil {
		slog.Error("Failed to get public key from GCP KMS", "error", err, "keyVersionID", s.keyVersionID)
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	block, _ := pem.Decode([]byte(pk.Pem))
	if block == nil {
		slog.Error("Failed to decode PEM block", "keyVersionID", s.keyVersionID)
		return nil, fmt.Errorf("failed to decode PEM block from public key")
	}

	s.fetchResp = &jwtsignerv1.FetchKeysResponse{
		Keys: []*jwtsignerv1.Key{
			{
				KeyId: keyID(s.keyVersionID),
				Key:   block.Bytes,
			},
		},
		DataTimestamp:      timestamppb.Now(),
		RefreshHintSeconds: 3600,
	}

	return s.fetchResp, nil
}

func (s *externalJWTServer) Sign(ctx context.Context, req *jwtsignerv1.SignJWTRequest) (*jwtsignerv1.SignJWTResponse, error) {
	decodedClaims, err := base64.RawURLEncoding.DecodeString(req.Claims)
	if err != nil {
		slog.Error("Failed to decode claims", "error", err)
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}
	slog.Info("Handling Sign request", "keyVersionID", s.keyVersionID, "key-id", keyID(s.keyVersionID), "claims", string(decodedClaims))
	headerJSON := fmt.Sprintf(`{"alg":"ES256","typ":"JWT","kid":"%s"}`, keyID(s.keyVersionID))
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	claimsB64 := req.Claims

	signingString := headerB64 + "." + claimsB64
	digest := sha256.Sum256([]byte(signingString))

	signResp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: s.keyVersionID,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if err != nil {
		slog.Error("AsymmetricSign failed", "error", err, "keyVersionID", s.keyVersionID)
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	// GCP KMS returns ASN.1 encoded ECDSA signature
	type ecdsaSignature struct {
		R, S *big.Int
	}
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signResp.Signature, &sig); err != nil {
		slog.Error("Failed to parse ASN.1 signature", "error", err)
		return nil, fmt.Errorf("failed to parse ASN.1 signature: %w", err)
	}

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// ES256 requires 64 bytes (32 bytes R, 32 bytes S)
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	signatureB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	slog.Info("Signed JWT")
	return &jwtsignerv1.SignJWTResponse{
		Header:    headerB64,
		Signature: signatureB64,
	}, nil
}

func keyID(keyVersionID string) string {
	h := sha256.Sum256([]byte(keyVersionID))
	return hex.EncodeToString(h[:])[0:12]
}
