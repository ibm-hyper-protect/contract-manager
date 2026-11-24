// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The import worker holds the catalog wrapping key, never the manager database.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ibm-hyper-protect/contract-manager/internal/secretflow"
	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

func main() {
	if err := run(); err != nil {
		slog.Error("secret import worker stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	socket := os.Getenv("SECRET_STORE_WORKER_SOCKET")
	keyPath := os.Getenv("SECRET_STORE_PRIVATE_KEY_FILE")
	if socket == "" || keyPath == "" {
		return errors.New("SECRET_STORE_WORKER_SOCKET and SECRET_STORE_PRIVATE_KEY_FILE are required")
	}
	key, err := secretstore.LoadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	info, err := secretstore.PublicKeyInfo(&key.PublicKey)
	if err != nil {
		return err
	}
	directory := filepath.Dir(socket)
	stat, err := os.Stat(directory)
	if err != nil {
		return err
	}
	if !stat.IsDir() || stat.Mode().Perm()&0077 != 0 {
		return errors.New("worker socket directory must be private (0700)")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	processor := &secretflow.Tool{Binary: os.Getenv("SECRET_STORE_PVSECRET_BIN"), Key: key,
		Certificates: strings.Fields(os.Getenv("SECRET_STORE_HOST_CERTIFICATES")), CRLs: strings.Fields(os.Getenv("SECRET_STORE_HOST_CRLS")),
		RootCA: os.Getenv("SECRET_STORE_ROOT_CA"), SigningKey: os.Getenv("SECRET_STORE_REQUEST_SIGNING_KEY"),
		AllowSimulation: os.Getenv("SECRET_STORE_ALLOW_SIMULATION") == "true", AllowInGuest: os.Getenv("SECRET_STORE_ALLOW_GUEST_CREATION") == "true"}
	if path := os.Getenv("SECRET_STORE_REQUEST_SIGNING_CERTIFICATE"); path != "" {
		processor.SigningCertificate, err = os.ReadFile(path)
		if err != nil {
			return err
		}
	}
	mux := http.NewServeMux()
	slots := make(chan struct{}, 1)
	operation := func(path string, run func(context.Context, []byte) (any, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			defer r.Body.Close()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				w.WriteHeader(503)
				json.NewEncoder(w).Encode(secretflow.Error{Code: "SECRET_WORKER_BUSY", Message: "Another preparation is running; retry shortly."})
				return
			}
			data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4*1024*1024))
			if e != nil {
				w.WriteHeader(400)
				json.NewEncoder(w).Encode(secretflow.Error{Code: "SECRET_JOB_INVALID", Message: "Preparation input exceeds its limit."})
				return
			}
			out, e := run(r.Context(), data)
			if e != nil {
				var typed *secretflow.Error
				if !errors.As(e, &typed) {
					typed = &secretflow.Error{Code: "SECRET_WORKER_REJECTED", Message: "The worker rejected the operation; no values were returned."}
				}
				w.WriteHeader(422)
				json.NewEncoder(w).Encode(typed)
				return
			}
			json.NewEncoder(w).Encode(out)
		})
	}
	operation("/target", func(ctx context.Context, data []byte) (any, error) {
		var t secretflow.Target
		if err := json.Unmarshal(data, &t); err != nil {
			return nil, err
		}
		return processor.ValidateTarget(ctx, t)
	})
	operation("/prepare", func(ctx context.Context, data []byte) (any, error) {
		var j secretflow.Job
		if err := json.Unmarshal(data, &j); err != nil {
			return nil, err
		}
		return processor.Prepare(ctx, j)
	})
	mux.HandleFunc("GET /import-key", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024))
		decoder.DisallowUnknownFields()
		var e secretstore.Envelope
		if err := decoder.Decode(&e); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n, err := secretstore.Verify(e, key)
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"byte_length": n})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 4 * time.Minute, IdleTimeout: 15 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	slog.Info("secret import worker ready", "fingerprint", info.Fingerprint, "socket", socket)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
