package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/grpc"
	jwtsignerv1 "k8s.io/externaljwt/apis/v1"
	kmsv2 "k8s.io/kms/apis/v2"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	kmsSocket := flag.String("kms-socket-path", "/var/run/kmsplugin/socket.sock", "Path to the KMS plugin Unix socket")
	jwtSocket := flag.String("jwt-socket-path", "/var/run/jwtplugin/socket.sock", "Path to the JWT plugin Unix socket")
	gcpKmsKey := flag.String("gcp-kms-key", "", "GCP KMS Key name for encryption/decryption")
	gcpJwtKeyVersion := flag.String("gcp-jwt-key-version", "", "GCP KMS Key Version name for JWT signing")
	flag.Parse()

	if *gcpKmsKey == "" || *gcpJwtKeyVersion == "" {
		slog.Error("Both --gcp-kms-key and --gcp-jwt-key-version must be set")
		os.Exit(1)
	}

	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		slog.Error("Failed to create KMS client", "error", err)
		os.Exit(1)
	}
	defer client.Close()

	kmsSvr := &kmsServer{
		client: client,
		keyID:  *gcpKmsKey,
	}

	jwtsSvr := &externalJWTServer{
		client:       client,
		keyVersionID: *gcpJwtKeyVersion,
	}

	kmsGrpcServer := grpc.NewServer()
	kmsv2.RegisterKeyManagementServiceServer(kmsGrpcServer, kmsSvr)

	jwtGrpcServer := grpc.NewServer()
	jwtsignerv1.RegisterExternalJWTSignerServer(jwtGrpcServer, jwtsSvr)

	startServer := func(socketPath string, server *grpc.Server, name string) {
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			slog.Error("Failed to remove existing socket", "socket", socketPath, "error", err)
			os.Exit(1)
		}

		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			slog.Error("Failed to listen on socket", "socket", socketPath, "error", err)
			os.Exit(1)
		}

		slog.Info("Starting server", "name", name, "socket", socketPath)
		go func() {
			if err := server.Serve(listener); err != nil {
				slog.Error("Failed to serve", "name", name, "socket", socketPath, "error", err)
				os.Exit(1)
			}
		}()
	}

	startServer(*kmsSocket, kmsGrpcServer, "KMS")
	startServer(*jwtSocket, jwtGrpcServer, "External JWT")

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("Shutting down...")
	kmsGrpcServer.GracefulStop()
	jwtGrpcServer.GracefulStop()
}
