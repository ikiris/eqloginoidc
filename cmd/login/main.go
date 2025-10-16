package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/ikiris/eqloginoidc/internal/login"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx := context.Background()

	if err := doStuff(ctx); err != nil {
		slog.Error("Failed to do stuff", slog.Any("error", err))
	}
}

func doStuff(ctx context.Context) error {
	// Database configuration
	dbHost := flag.String("db-host", getEnv("DB_HOST", "localhost"), "Database host")
	dbPort := flag.String("db-port", getEnv("DB_PORT", "3306"), "Database port")
	dbUser := flag.String("db-user", getEnv("DB_USER", "quarm"), "Database user")
	dbPassword := getEnv("DB_PASSWORD", "quarm")
	dbName := flag.String("db-name", getEnv("DB_NAME", "quarm"), "Database name")
	port := flag.Uint("port", 8443, "Port to listen on")
	configPath := flag.String("config", getEnv("CLIENT_CONFIG", "clients.yaml"), "Path to client configuration file")
	certPath := flag.String("cert-file", getEnv("CERT_FILE", "cert.pem"), "Path to certificate file")
	keyPath := flag.String("key-file", getEnv("KEY_FILE", "key.pem"), "Path to private key file")

	flag.Parse()

	// Initialize database connection
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true",
		*dbUser, dbPassword, *dbHost, *dbPort, *dbName)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			slog.Error("Failed to close database", slog.Any("error", err))
		}
	}()

	// Initialize OIDC provider server
	server, err := login.New(ctx, db, *configPath, *certPath, *keyPath)
	if err != nil {
		log.Fatalf("Failed to create login server: %v", err)
	}

	// Register routes
	server.Register()

	slog.InfoContext(ctx, "Starting OIDC provider server with TLS on port", "port", strconv.Itoa(int(*port)))

	tCtx, tCancel := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer tCancel()

	// Get TLS configuration from the server
	tlsConfig, err := server.GetTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %w", err)
	}

	hSrv := &http.Server{
		Addr:      ":" + strconv.Itoa(int(*port)),
		TLSConfig: tlsConfig,
	}

	errG, gCtx := errgroup.WithContext(ctx)
	errG.Go(func() error {
		if err := hSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("failed to listen and serve TLS: %w", err)
		}

		return nil
	})

	errG.Go(func() error {
		select {
		case <-tCtx.Done():
		case <-gCtx.Done():
		}

		sCtx, sCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer sCancel()

		if err := hSrv.Shutdown(sCtx); err != nil {
			return fmt.Errorf("failed to shutdown http server: %w", err)
		}

		return nil
	})

	if err := errG.Wait(); err != nil {
		return fmt.Errorf("failed to listen and serve: %w", err)
	}

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
