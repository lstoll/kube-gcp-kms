package main

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"sort"
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

	client    *kms.KeyManagementClient
	keyName   string        // CryptoKey resource name (not a specific version)
	keyLeadIn time.Duration // minimum age of a version before it is used for signing

	// cachedKeys holds all ENABLED EC_SIGN_P256_SHA256 versions.
	// cachedSigningVersion is the version used for signing.
	// Both are refreshed together on cache expiry.
	cachedKeys           []keyEntry
	cachedSigningVersion string
	cacheExpiry          time.Time
	cacheMu              sync.RWMutex
}

func (s *externalJWTServer) Metadata(ctx context.Context, req *jwtsignerv1.MetadataRequest) (*jwtsignerv1.MetadataResponse, error) {
	slog.Info("Handling Metadata request")
	return &jwtsignerv1.MetadataResponse{
		MaxTokenExpirationSeconds: int64((6 * time.Hour).Seconds()),
	}, nil
}

// refreshCache fetches all ENABLED EC_SIGN_P256_SHA256 key versions from GCP KMS.
// The signing version is the newest version whose CreateTime is at least keyLeadIn ago,
// giving time for the public key to propagate before it is used for signing.
// Callers must not hold cacheMu.
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

	type versionEntry struct {
		keyEntry
		createTime time.Time
	}

	var versions []versionEntry
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

		ct := time.Time{}
		if v.CreateTime != nil {
			ct = v.CreateTime.AsTime()
		}
		versions = append(versions, versionEntry{
			keyEntry:   keyEntry{versionName: v.Name, keyDER: block.Bytes},
			createTime: ct,
		})
	}

	if len(versions) == 0 {
		return fmt.Errorf("no enabled EC_SIGN_P256_SHA256 versions found for %s", s.keyName)
	}

	// Sort newest-first so we can pick the newest version that has passed the lead-in window.
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].createTime.After(versions[j].createTime)
	})

	cutoff := time.Now().Add(-s.keyLeadIn)
	signingVersion := ""
	for _, ve := range versions {
		if ve.createTime.Before(cutoff) {
			signingVersion = ve.versionName
			break
		}
	}
	if signingVersion == "" {
		// No version has passed the lead-in period (e.g. initial setup). Use the
		// oldest available version to minimise the chance of signing with a brand-new key.
		signingVersion = versions[len(versions)-1].versionName
		slog.Warn("No key version has passed the lead-in period; using oldest enabled version for signing",
			"keyName", s.keyName, "signingVersion", signingVersion, "keyLeadIn", s.keyLeadIn)
	}

	entries := make([]keyEntry, len(versions))
	for i, ve := range versions {
		entries[i] = ve.keyEntry
	}

	s.cachedKeys = entries
	s.cachedSigningVersion = signingVersion
	s.cacheExpiry = time.Now().Add(keyCacheTTL)
	slog.Info("Refreshed JWT key cache", "keyName", s.keyName, "signingVersion", signingVersion, "numVersions", len(entries))
	return nil
}

func (s *externalJWTServer) getCache(ctx context.Context) (keys []keyEntry, signingVersion string, err error) {
	s.cacheMu.RLock()
	keys, signingVersion, expiry := s.cachedKeys, s.cachedSigningVersion, s.cacheExpiry
	s.cacheMu.RUnlock()

	if keys != nil && time.Now().Before(expiry) {
		return keys, signingVersion, nil
	}

	if err := s.refreshCache(ctx); err != nil {
		return nil, "", err
	}

	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()
	return s.cachedKeys, s.cachedSigningVersion, nil
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

	_, signingVersion, err := s.getCache(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	kid := keyID(signingVersion)
	slog.Info("Handling Sign request", "keyName", s.keyName, "signingVersion", signingVersion, "kid", kid)

	headerJSON := fmt.Sprintf(`{"alg":"ES256","typ":"JWT","kid":"%s"}`, kid)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

	signingString := headerB64 + "." + req.Claims
	digest := sha256.Sum256([]byte(signingString))

	signResp, err := s.client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: signingVersion,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if err != nil {
		slog.Error("AsymmetricSign failed", "error", err, "signingVersion", signingVersion)
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
	return base64.RawURLEncoding.EncodeToString(h[:9])
}
