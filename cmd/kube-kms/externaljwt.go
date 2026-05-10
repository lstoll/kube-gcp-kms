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
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/types/known/timestamppb"
	jwtsignerv1 "k8s.io/externaljwt/apis/v1"
)

const (
	keyRefreshHintSeconds = 3600
	keyCacheTTL           = keyRefreshHintSeconds * time.Second
)

type keyEntry struct {
	versionName string
	keyDER      []byte
}

type externalJWTServer struct {
	jwtsignerv1.UnimplementedExternalJWTSignerServer

	client  *kms.KeyManagementClient
	keyName string // CryptoKey resource name (not a specific version)

	// cachedKeys holds all ENABLED EC_SIGN_P256_SHA256 versions.
	// cachedPrimaryVersion is the version used for signing.
	// Both are refreshed together on cache expiry.
	cachedKeys           []keyEntry
	cachedPrimaryVersion string
	cacheExpiry          time.Time
	cacheMu              sync.RWMutex
}

func (s *externalJWTServer) Metadata(ctx context.Context, req *jwtsignerv1.MetadataRequest) (*jwtsignerv1.MetadataResponse, error) {
	slog.Info("Handling Metadata request")
	return &jwtsignerv1.MetadataResponse{
		MaxTokenExpirationSeconds: int64((6 * time.Hour).Seconds()),
	}, nil
}

// refreshCache fetches the primary signing version and all ENABLED EC_SIGN_P256_SHA256
// public keys from GCP KMS. Callers must not hold cacheMu.
func (s *externalJWTServer) refreshCache(ctx context.Context) (err error) {
	if s.client == nil {
		return fmt.Errorf("no KMS client available")
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	if s.cachedKeys != nil && time.Now().Before(s.cacheExpiry) {
		return nil
	}

	defer func() {
		if err != nil {
			keyCacheRefreshTotal.WithLabelValues("error").Inc()
		} else {
			keyCacheRefreshTotal.WithLabelValues("success").Inc()
		}
	}()

	key, err := s.client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: s.keyName})
	if err != nil {
		return fmt.Errorf("get crypto key: %w", err)
	}
	if key.Primary == nil {
		return fmt.Errorf("key %s has no primary version", s.keyName)
	}

	var entries []keyEntry
	it := s.client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{
		Parent: s.keyName,
		Filter: "state=ENABLED",
	})
	for {
		v, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("list key versions: %w", err)
		}
		if v.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
			continue
		}

		pk, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: v.Name})
		if err != nil {
			return fmt.Errorf("get public key for %s: %w", v.Name, err)
		}

		block, _ := pem.Decode([]byte(pk.Pem))
		if block == nil {
			return fmt.Errorf("failed to decode PEM for version %s", v.Name)
		}

		entries = append(entries, keyEntry{versionName: v.Name, keyDER: block.Bytes})
	}

	if len(entries) == 0 {
		return fmt.Errorf("no enabled EC_SIGN_P256_SHA256 versions found for %s", s.keyName)
	}

	s.cachedKeys = entries
	s.cachedPrimaryVersion = key.Primary.Name
	s.cacheExpiry = time.Now().Add(keyCacheTTL)
	slog.Info("Refreshed JWT key cache", "keyName", s.keyName, "primaryVersion", s.cachedPrimaryVersion, "numVersions", len(entries))
	return nil
}

func (s *externalJWTServer) getCache(ctx context.Context) (keys []keyEntry, primaryVersion string, err error) {
	s.cacheMu.RLock()
	keys, primaryVersion, expiry := s.cachedKeys, s.cachedPrimaryVersion, s.cacheExpiry
	s.cacheMu.RUnlock()

	if keys != nil && time.Now().Before(expiry) {
		return keys, primaryVersion, nil
	}

	if err := s.refreshCache(ctx); err != nil {
		return nil, "", err
	}

	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.cachedKeys, s.cachedPrimaryVersion, nil
}

func (s *externalJWTServer) FetchKeys(ctx context.Context, req *jwtsignerv1.FetchKeysRequest) (_ *jwtsignerv1.FetchKeysResponse, err error) {
	slog.Info("Handling FetchKeys request", "keyName", s.keyName)
	defer func() {
		if err != nil {
			fetchKeysTotal.WithLabelValues("error").Inc()
		} else {
			fetchKeysTotal.WithLabelValues("success").Inc()
		}
	}()

	keys, _, err := s.getCache(ctx)
	if err != nil {
		slog.Error("Failed to fetch keys from GCP KMS", "error", err)
		return nil, err
	}

	resp := &jwtsignerv1.FetchKeysResponse{
		DataTimestamp:      timestamppb.Now(),
		RefreshHintSeconds: keyRefreshHintSeconds,
	}
	for _, e := range keys {
		resp.Keys = append(resp.Keys, &jwtsignerv1.Key{
			KeyId: keyID(e.versionName),
			Key:   e.keyDER,
		})
	}
	return resp, nil
}

func (s *externalJWTServer) Sign(ctx context.Context, req *jwtsignerv1.SignJWTRequest) (_ *jwtsignerv1.SignJWTResponse, err error) {
	start := time.Now()
	defer func() {
		signDuration.Observe(time.Since(start).Seconds())
		if err != nil {
			signTotal.WithLabelValues("error").Inc()
		} else {
			signTotal.WithLabelValues("success").Inc()
		}
	}()

	_, primaryVersion, err := s.getCache(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary signing key: %w", err)
	}

	kid := keyID(primaryVersion)
	slog.Info("Handling Sign request", "keyName", s.keyName, "primaryVersion", primaryVersion, "kid", kid)

	headerJSON := fmt.Sprintf(`{"alg":"ES256","typ":"JWT","kid":"%s"}`, kid)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	signingString := headerB64 + "." + req.Claims
	digest := sha256.Sum256([]byte(signingString))

	signResp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: primaryVersion,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if err != nil {
		slog.Error("AsymmetricSign failed", "error", err, "primaryVersion", primaryVersion)
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

	slog.Info("Signed JWT successfully", "kid", kid)
	return &jwtsignerv1.SignJWTResponse{
		Header:    headerB64,
		Signature: base64.RawURLEncoding.EncodeToString(sigBytes),
	}, nil
}

// keyID returns a short, stable identifier derived from the key version resource name.
func keyID(keyVersionName string) string {
	h := sha256.Sum256([]byte(keyVersionName))
	return hex.EncodeToString(h[:])[0:12]
}
