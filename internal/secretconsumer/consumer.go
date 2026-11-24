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

// Package secretconsumer provides a single pinned workload binding over a private
// Unix socket. It never exposes store management, a caller-selected ID, or files.
package secretconsumer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string        { return e.Code + ": " + e.Message }
func fail(code, message string) error { return &Error{code, message} }

type Capabilities struct {
	Kernel uint64 `json:"kernel_mask"`
	UV     uint64 `json:"uv_mask"`
}

func (c Capabilities) Retrieve() bool { return c.Kernel&(1<<5) != 0 && c.UV&(1<<5) != 0 }

type Server struct {
	ID, Kind, Mode string
	Read           func(context.Context) ([]byte, error)
}

func (s Server) Validate() error {
	if s.Kind != "retrievable" {
		return fail("SECRET_NOT_RETRIEVABLE", "Association secrets bind external resources and cannot be retrieved as plaintext.")
	}
	if len(s.ID) != 66 || !strings.HasPrefix(s.ID, "0x") {
		return fail("SECRET_ID_INVALID", "Provide the pinned 0x-prefixed UV ID, not a catalog UUID or contract index.")
	}
	if _, e := hex.DecodeString(s.ID[2:]); e != nil {
		return fail("SECRET_ID_INVALID", "The pinned UV ID must contain 32 bytes of hex.")
	}
	if s.Mode != "NATIVE" && s.Mode != "SIMULATION" {
		return fail("SECRET_MODE_REQUIRED", "Choose NATIVE or explicit SIMULATION; fallback is never automatic.")
	}
	if s.Read == nil {
		return fail("SECRET_RETRIEVE_UNAVAILABLE", "No approved consumer backend is configured.")
	}
	return nil
}
func (s Server) Handler() (http.Handler, error) {
	if e := s.Validate(); e != nil {
		return nil, e
	}
	slots := make(chan struct{}, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Secret-Mode", s.Mode)
		sendError := func(status int, e error) {
			var typed *Error
			if !errors.As(e, &typed) {
				typed = &Error{"SECRET_RETRIEVE_FAILED", "The pinned secret could not be retrieved; no value was returned."}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(typed)
		}
		if r.URL.RawQuery != "" || r.ContentLength > 0 {
			sendError(400, fail("SECRET_BINDING_FIXED", "This socket serves one configured binding and accepts no ID or parameters."))
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			sendError(503, fail("SECRET_CONSUMER_BUSY", "Too many concurrent reads."))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		value, e := s.Read(ctx)
		defer clear(value)
		if e != nil {
			sendError(503, e)
			return
		}
		if len(value) > 8192 {
			sendError(503, fail("SECRET_RETRIEVE_INVALID", "Retrieved output exceeds the UV limit."))
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
		w.Write(value)
	})
	return mux, nil
}

// Listen requires an already-provisioned private directory and never removes an
// existing socket. Mount this socket only into its intended workload consumer.
func (s Server) Listen(socket string) (net.Listener, error) {
	if e := s.Validate(); e != nil {
		return nil, e
	}
	stat, e := os.Stat(filepath.Dir(socket))
	if e != nil || !stat.IsDir() || stat.Mode().Perm()&0077 != 0 {
		return nil, fail("SECRET_SOCKET_UNSAFE", "Provision a private 0700 socket directory for this consumer.")
	}
	ln, e := net.Listen("unix", socket)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(socket, 0600); e != nil {
		ln.Close()
		return nil, e
	}
	return ln, nil
}

type boundedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	left := 8192 - b.Len()
	if len(p) > left {
		b.overflow = true
		p = p[:left]
	}
	b.Buffer.Write(p)
	return n, nil
}
func Native(binary, id string) (Server, error) {
	server := Server{ID: id, Kind: "retrievable", Mode: "NATIVE", Read: func(context.Context) ([]byte, error) { return nil, nil }}
	if e := server.Validate(); e != nil {
		return Server{}, e
	}
	caps, e := NativeCapabilities()
	if e != nil {
		return Server{}, e
	}
	if !caps.Retrieve() {
		return Server{}, fail("UV_RETRIEVE_UNSUPPORTED", "This guest kernel or Ultravisor does not support Retrieve. Use a supported target; no software fallback was selected.")
	}
	path, e := exec.LookPath(binary)
	if e != nil {
		return Server{}, fail("PVSECRET_UNAVAILABLE", "Install IBM pvsecret with the retrieve subcommand in this guest.")
	}
	server.Read = func(ctx context.Context) ([]byte, error) {
		cmd := exec.CommandContext(ctx, path, "retrieve", "--inform", "hex", "--outform", "bin", "--output", "/dev/stdout", id)
		out := &boundedBuffer{}
		cmd.Stdout = out
		cmd.Stderr = io.Discard
		if e := cmd.Run(); e != nil || out.overflow {
			clear(out.Bytes())
			return nil, fail("SECRET_RETRIEVE_FAILED", "The UV did not return this pinned secret. Check the imported request, ID, type and guest access.")
		}
		return out.Bytes(), nil
	}
	return server, nil
}
