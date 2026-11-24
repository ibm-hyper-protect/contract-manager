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
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

var ErrUnavailable = errors.New("secret import worker unavailable")

type Verifier interface {
	Info(context.Context) (ImportKey, error)
	Verify(context.Context, Envelope) (int, error)
}
type Client struct {
	http        *http.Client
	fingerprint string
}

func NewClient(socket, fingerprint string) *Client {
	return &Client{fingerprint: fingerprint, http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
		MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2,
	}}}
}
func (c *Client) call(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://secret-worker"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("sealed import rejected by worker")
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16*1024)).Decode(output)
}
func (c *Client) Info(ctx context.Context) (ImportKey, error) {
	var out ImportKey
	err := c.call(ctx, http.MethodGet, "/import-key", nil, &out)
	if err != nil {
		return ImportKey{}, err
	}
	block, rest := pem.Decode([]byte(out.PublicKeyPEM))
	if block == nil || len(rest) != 0 {
		return ImportKey{}, ErrUnavailable
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ImportKey{}, ErrUnavailable
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return ImportKey{}, ErrUnavailable
	}
	verified, err := PublicKeyInfo(key)
	if err != nil || c.fingerprint == "" || verified.Fingerprint != c.fingerprint || out.Fingerprint != verified.Fingerprint || out.KeyID != verified.KeyID || out.MaxBytes != MaxSecretBytes {
		return ImportKey{}, ErrUnavailable
	}
	return out, nil
}
func (c *Client) Verify(ctx context.Context, e Envelope) (int, error) {
	if c.fingerprint == "" || e.KeyID != c.fingerprint {
		return 0, errors.New("sealed import key does not match configured worker")
	}
	var out struct {
		ByteLength int `json:"byte_length"`
	}
	err := c.call(ctx, http.MethodPost, "/verify", e, &out)
	return out.ByteLength, err
}
