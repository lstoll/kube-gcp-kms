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

const (
	keyRefreshHintSeconds = 3600
	keyCacheTTL           = keyRefreshHintSeconds * time.Second
)

type externalJWTServer struct {
	jwtsignerv1.UnimplementedExternalJWTSignerServer

	client       *kms.KeyManagementClient
	keyVersionID string

	// cachedKeyDER is the DER-encoded public key, nil until first fetch.
	// Refreshed when cacheExpiry passes, aligned with keyRefreshHintSeconds.
	cachedKeyDER []byte
	cacheExpiry  time.Time
	cacheMu      sync.RWMutex
}

func (s *externalJWTServer) Metadata(ctx context.Context, req *jwtsignerv1.MetadataRequest) (*jwtsignerv1.MetadataResponse, error) {
	slog.Info("Handling Metadata request")
	return &jwtsignerv1.MetadataResponse{
		MaxTokenExpirationSeconds: int64((6 * time.Hour).Seconds()),
	}, nil
}

func (s *externalJWTServer) FetchKeys(ctx context.Context, req *jwtsignerv1.FetchKeysRequest) (*jwtsignerv1.FetchKeysResponse, error) {
	slog.Info("Handling FetchKeys request", "keyVersionID", s.keyVersionID)

	s.cacheMu.RLock()
	keyDER, expiry := s.cachedKeyDER, s.cacheExpiry
	s.cacheMu.RUnlock()

	if keyDER == nil || time.Now().After(expiry) {
		var err error
		keyDER, err = s.refreshKeyDER(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &jwtsignerv1.FetchKeysResponse{
		Keys: []*jwtsignerv1.Key{
			{
				KeyId: keyID(s.keyVersionID),
				Key:   keyDER,
			},
		},
		DataTimestamp:      timestamppb.Now(),
		RefreshHintSeconds: keyRefreshHintSeconds,
	}, nil
}

func (s *externalJWTServer) refreshKeyDER(ctx context.Context) ([]byte, error) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if s.cachedKeyDER != nil && time.Now().Before(s.cacheExpiry) {
		return s.cachedKeyDER, nil
	}

	pk, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: s.keyVersionID,
	})
	if err != nil {
		slog.Error("Failed to get public key from GCP KMS", "error", err, "keyVersionID", s.keyVersionID)
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	if pk.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
		return nil, fmt.Errorf("unsupported key algorithm %s: only EC_SIGN_P256_SHA256 (ES256) is supported", pk.Algorithm)
	}

	block, _ := pem.Decode([]byte(pk.Pem))
	if block == nil {
		slog.Error("Failed to decode PEM block", "keyVersionID", s.keyVersionID)
		return nil, fmt.Errorf("failed to decode PEM block from public key")
	}

	s.cachedKeyDER = block.Bytes
	s.cacheExpiry = time.Now().Add(keyCacheTTL)
	return s.cachedKeyDER, nil
}

func (s *externalJWTServer) Sign(ctx context.Context, req *jwtsignerv1.SignJWTRequest) (*jwtsignerv1.SignJWTResponse, error) {
	slog.Info("Handling Sign request", "keyVersionID", s.keyVersionID, "kid", keyID(s.keyVersionID))

	headerJSON := fmt.Sprintf(`{"alg":"ES256","typ":"JWT","kid":"%s"}`, keyID(s.keyVersionID))
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	signingString := headerB64 + "." + req.Claims
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

	// GCP KMS returns an ASN.1 DER-encoded ECDSA signature; JWT ES256 requires
	// the raw 64-byte (R||S) encoding.
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

	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	slog.Info("Signed JWT successfully")
	return &jwtsignerv1.SignJWTResponse{
		Header:    headerB64,
		Signature: base64.RawURLEncoding.EncodeToString(sigBytes),
	}, nil
}

// keyID returns a short, stable identifier derived from the key version resource name.
func keyID(keyVersionID string) string {
	h := sha256.Sum256([]byte(keyVersionID))
	return hex.EncodeToString(h[:])[0:12]
}
