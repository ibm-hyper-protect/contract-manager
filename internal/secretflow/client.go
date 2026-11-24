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

package secretflow

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ibm-hyper-protect/contract-manager/internal/secretstore"
)

// Client uses a private Unix socket and pins the worker wrapping identity.
// The socket is a trusted local boundary, never an externally served API.
type Client struct {
	http     *http.Client
	verifier *secretstore.Client
}

func NewClient(socket, fingerprint string) *Client {
	return &Client{verifier: secretstore.NewClient(socket, fingerprint), http: &http.Client{Timeout: 4 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 1}}}
}
func (c *Client) call(ctx context.Context, path string, in, out any) error {
	if _, err := c.verifier.Info(ctx); err != nil {
		return Fail("SECRET_WORKER_UNAVAILABLE", "The pinned preparation worker is unavailable.")
	}
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://secret-worker"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Fail("SECRET_WORKER_UNAVAILABLE", "The preparation worker did not complete the operation.")
	}
	defer resp.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024))
	if resp.StatusCode != 200 {
		var e Error
		if decoder.Decode(&e) != nil || e.Code == "" {
			return Fail("SECRET_WORKER_REJECTED", "The preparation worker rejected the operation.")
		}
		return &e
	}
	return decoder.Decode(out)
}
func (c *Client) ValidateTarget(ctx context.Context, t Target) (TargetEvidence, error) {
	var out TargetEvidence
	e := c.call(ctx, "/target", t, &out)
	return out, e
}
func (c *Client) Prepare(ctx context.Context, j Job) (Result, error) {
	var out Result
	e := c.call(ctx, "/prepare", j, &out)
	return out, e
}
