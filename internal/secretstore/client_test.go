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

package secretstore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkerClientPinsActualPublicKey(t *testing.T) {
	key := keyForTest(t)
	info, err := PublicKeyInfo(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Keep Unix paths short on macOS (sun_path is limited to 104 bytes).
	dir, err := os.MkdirTemp("", "cw-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "w.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /import-key", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(info) })
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	server := &http.Server{Handler: mux}
	defer server.Close()
	go server.Serve(listener)
	client := NewClient(socket, info.Fingerprint)
	if _, err = client.Info(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = NewClient(socket, "untrusted").Info(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unpinned worker accepted: %v", err)
	}
	if _, err = NewClient(socket, "").Info(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing pin accepted")
	}
	e := sealForTest(t, key, []byte("dummy"))
	if _, err = client.Verify(context.Background(), e); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("worker outage not distinguished: %v", err)
	}
	e.KeyID = "different"
	if _, err = client.Verify(context.Background(), e); err == nil {
		t.Fatal("untrusted envelope key accepted")
	}
}
