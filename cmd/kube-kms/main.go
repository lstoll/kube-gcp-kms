package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	gcpJwtKey   := flag.String("gcp-jwt-key", "", "GCP KMS Key name for JWT signing (all enabled versions are used for verification; the primary version signs)")
	metricsAddr := flag.String("metrics-addr", ":9090", "Address to serve Prometheus metrics on (/metrics)")
	flag.Parse()

	if *gcpKmsKey == "" || *gcpJwtKey == "" {
		slog.Error("Both --gcp-kms-key and --gcp-jwt-key must be set")
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
		client:  client,
		keyName: *gcpJwtKey,
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

		if err := os.Chmod(socketPath, 0600); err != nil {
			slog.Error("Failed to set socket permissions", "socket", socketPath, "error", err)
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

	slog.Info("Starting metrics server", "addr", *metricsAddr)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(*metricsAddr, mux); err != nil {
			slog.Error("Metrics server failed", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("Shutting down...")

	gracefulStop := func(svr *grpc.Server) {
		done := make(chan struct{})
		go func() { svr.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			svr.Stop()
		}
	}

	var wg sync.WaitGroup
	for _, svr := range []*grpc.Server{kmsGrpcServer, jwtGrpcServer} {
		wg.Add(1)
		go func(s *grpc.Server) {
			defer wg.Done()
			gracefulStop(s)
		}(svr)
	}
	wg.Wait()
}
