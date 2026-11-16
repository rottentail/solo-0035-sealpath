package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sealpath/internal/repository"
	"sealpath/internal/transport"
	"syscall"
	"time"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8435", "HTTP listen address")
	statePath := flag.String("state", "var/sealpath-state.json", "single-process state path")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	store, err := repository.Open(*statePath)
	if err != nil {
		logger.Error("cannot open state", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Addr: *address, Handler: transport.New(store, logger).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		<-signals
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		close(done)
	}()
	logger.Info("service ready", "address", *address)
	if err = server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
	<-done
}
