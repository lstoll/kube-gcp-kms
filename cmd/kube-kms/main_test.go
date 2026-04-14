package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	jwtsignerv1 "k8s.io/externaljwt/apis/v1"
	kmsv2 "k8s.io/kms/apis/v2"
)

func TestServers(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	kmsSocket := filepath.Join(tmpDir, "kms.sock")
	jwtSocket := filepath.Join(tmpDir, "jwt.sock")

	kmsKey := os.Getenv("TEST_GCP_KMS_KEY")
	jwtKeyVer := os.Getenv("TEST_GCP_JWT_KEY_VERSION")

	var client *kms.KeyManagementClient
	var err error

	if kmsKey != "" && jwtKeyVer != "" {
		client, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			t.Fatalf("Failed to create KMS client: %v", err)
		}
		defer client.Close()
	} else {
		t.Log("TEST_GCP_KMS_KEY or TEST_GCP_JWT_KEY_VERSION not set, skipping integration test parts that require GCP")
		kmsKey = "projects/test/locations/global/keyRings/test/cryptoKeys/test"
		jwtKeyVer = "projects/test/locations/global/keyRings/test/cryptoKeys/test/cryptoKeyVersions/1"
	}

	kmsSvr := &kmsServer{
		client: client,
		keyID:  kmsKey,
	}
	jwtsSvr := &externalJWTServer{
		client:       client,
		keyVersionID: jwtKeyVer,
	}

	kmsGrpcServer := grpc.NewServer()
	kmsv2.RegisterKeyManagementServiceServer(kmsGrpcServer, kmsSvr)

	jwtGrpcServer := grpc.NewServer()
	jwtsignerv1.RegisterExternalJWTSignerServer(jwtGrpcServer, jwtsSvr)

	startServer := func(socketPath string, server *grpc.Server, name string) {
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("Failed to listen on %s: %v", socketPath, err)
		}
		go func() {
			if err := server.Serve(listener); err != nil {
				t.Logf("Failed to serve %s on %s: %v", name, socketPath, err)
			}
		}()
	}

	startServer(kmsSocket, kmsGrpcServer, "KMS")
	startServer(jwtSocket, jwtGrpcServer, "External JWT")

	defer kmsGrpcServer.Stop()
	defer jwtGrpcServer.Stop()

	// Wait a tiny bit for listeners to start
	time.Sleep(100 * time.Millisecond)

	kmsConn, err := grpc.NewClient("unix://"+kmsSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to create KMS client: %v", err)
	}
	defer kmsConn.Close()

	kmsClient := kmsv2.NewKeyManagementServiceClient(kmsConn)
	status, err := kmsClient.Status(ctx, &kmsv2.StatusRequest{})
	if err != nil {
		t.Fatalf("Status check failed: %v", err)
	}
	if status.Healthz != "ok" {
		t.Fatalf("Expected healthz ok, got %s", status.Healthz)
	}

	jwtConn, err := grpc.NewClient("unix://"+jwtSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to create JWT client: %v", err)
	}
	defer jwtConn.Close()

	jwtClient := jwtsignerv1.NewExternalJWTSignerClient(jwtConn)
	metadata, err := jwtClient.Metadata(ctx, &jwtsignerv1.MetadataRequest{})
	if err != nil {
		t.Fatalf("Metadata check failed: %v", err)
	}
	if metadata.MaxTokenExpirationSeconds == 0 {
		t.Fatalf("Expected MaxTokenExpirationSeconds, got 0")
	}

	if client != nil {
		t.Run("EncryptDecrypt", func(t *testing.T) {
			plaintext := []byte("hello world")
			encResp, err := kmsClient.Encrypt(ctx, &kmsv2.EncryptRequest{
				Uid:       "1",
				Plaintext: plaintext,
			})
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decResp, err := kmsClient.Decrypt(ctx, &kmsv2.DecryptRequest{
				Uid:        "2",
				Ciphertext: encResp.Ciphertext,
			})
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if string(decResp.Plaintext) != string(plaintext) {
				t.Fatalf("Decrypted plaintext mismatch: got %v, want %v", decResp.Plaintext, plaintext)
			}
		})

		t.Run("SignFetch", func(t *testing.T) {
			signResp, err := jwtClient.Sign(ctx, &jwtsignerv1.SignJWTRequest{
				Claims: "test-claims",
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}
			if signResp.Signature == "" {
				t.Fatalf("Empty signature returned")
			}

			fetchResp, err := jwtClient.FetchKeys(ctx, &jwtsignerv1.FetchKeysRequest{})
			if err != nil {
				t.Fatalf("FetchKeys failed: %v", err)
			}
			if len(fetchResp.Keys) == 0 {
				t.Fatalf("No keys returned")
			}
		})
	}
}
