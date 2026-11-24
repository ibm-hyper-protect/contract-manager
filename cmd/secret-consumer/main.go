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

// secret-consumer exposes exactly one native retrievable binding to its workload.
// It never writes secret values to disk or provides an administration endpoint.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ibm-hyper-protect/contract-manager/internal/secretconsumer"
)

func main() {
	if e := run(); e != nil {
		slog.Error("secret consumer stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	id := flag.String("id", "", "Pinned 0x-prefixed retrievable UV secret ID")
	socket := flag.String("socket", "", "Private Unix socket for this consumer")
	binary := flag.String("pvsecret", "pvsecret", "IBM pvsecret executable")
	flag.Parse()
	server, e := secretconsumer.Native(*binary, *id)
	if e != nil {
		return e
	}
	handler, e := server.Handler()
	if e != nil {
		return e
	}
	ln, e := server.Listen(*socket)
	if e != nil {
		return e
	}
	defer ln.Close()
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 8 * time.Second, IdleTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdown)
	}()
	slog.Info("native secret consumer ready; values are never logged")
	e = httpServer.Serve(ln)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
