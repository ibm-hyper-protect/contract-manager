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

package secretconsumer

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConsumerMemoryOnlyFixedBinding(t *testing.T) {
	value := []byte(" \x00\xff dummy binary value\n ")
	var buffer []byte
	calls := 0
	s := Server{ID: "0x" + strings.Repeat("a", 64), Kind: "retrievable", Mode: "SIMULATION", Read: func(context.Context) ([]byte, error) {
		calls++
		buffer = append([]byte{}, value...)
		return buffer, nil
	}}
	h, e := s.Handler()
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/secret", nil))
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), value) || w.Header().Get("X-Secret-Mode") != "SIMULATION" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("binary value or mode lost")
	}
	if !bytes.Equal(buffer, make([]byte, len(buffer))) {
		t.Fatal("temporary response value not cleared")
	}
	for _, path := range []string{"/secret?id=another", "/list", "/add", "/lock"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code == 200 {
			t.Fatal("unapproved store operation")
		}
	}
	if calls != 1 {
		t.Fatal("unapproved request reached backend")
	}
	s.Kind = "association"
	if _, e = s.Handler(); e == nil {
		t.Fatal("association exposed for plaintext retrieval")
	}
}
func TestNativeConsumerFailsClosed(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "s390x" {
		_, e := Native("pvsecret", "0x"+strings.Repeat("a", 64))
		typed, ok := e.(*Error)
		if !ok || typed.Code != "SE_GUEST_REQUIRED" {
			t.Fatalf("unsupported native execution accepted: %v", e)
		}
	}
	for _, c := range []Capabilities{{0x1f, 0x1e}, {0x3f, 0x1e}, {0x1f, 0x3e}} {
		if c.Retrieve() {
			t.Fatal("missing kernel or UV support accepted")
		}
	}
	if !(Capabilities{0x3f, 0x3e}).Retrieve() {
		t.Fatal("supported masks rejected")
	}
}
func TestPrivateConsumerSocket(t *testing.T) {
	s := Server{ID: "0x" + strings.Repeat("a", 64), Kind: "retrievable", Mode: "SIMULATION", Read: func(context.Context) ([]byte, error) { return nil, nil }}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	p := filepath.Join(dir, "control.sock")
	ln, e := s.Listen(p)
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	if _, e = s.Listen(p); e == nil {
		t.Fatal("existing socket replaced")
	}
	os.Chmod(dir, 0755)
	if _, e = s.Listen(filepath.Join(dir, "other.sock")); e == nil {
		t.Fatal("public consumer directory accepted")
	}
}
