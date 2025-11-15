package prism

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

const ReadHeaderTimeout = 3 * time.Second

type ReloadableServer struct {
	Addr string
	Handler http.Handler
	TLSConfig *tls.Config
	ReadHeaderTimeout time.Duration
	srv    *http.Server
	mu     sync.Mutex
}

func NewReloadableServer(addr string, handler http.Handler, tlsConfig *tls.Config) *ReloadableServer {
	return &ReloadableServer{
		Addr: addr,
		Handler: handler,
		TLSConfig: tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
	}
}

func (rs *ReloadableServer) Start(h http.Handler, n Notifier) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.srv != nil {
		return // errors.New("Server is already running.")
	}

	if h != nil {
		rs.Handler = h
	}

	rs.srv = &http.Server{
		Addr:    rs.Addr,
		Handler: rs.Handler,
		TLSConfig: rs.TLSConfig,
		ReadHeaderTimeout: rs.ReadHeaderTimeout,
	}

	log.Printf("Starting server on %s\n", rs.Addr)
	go func() {
		err := rs.srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			n.NotifyError(err)
			return
		}

		n.NotifyDone()
	}()
}

func (rs *ReloadableServer) Shutdown(ctx context.Context) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.srv == nil {
		return nil
	}

	log.Println("Shutting down server gracefully...")

	err := rs.srv.Shutdown(ctx)
	rs.srv = nil
	return err
}

func (rs *ReloadableServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rs.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}

func (rs *ReloadableServer) Reload(h http.Handler, n Notifier) error {
	log.Println("Restarting server...")
	if err := rs.Stop(); err != nil {
		return fmt.Errorf("stop failed: %w", err)
	}
	time.Sleep(500 * time.Millisecond) // 少し待ってから再起動
	rs.Start(h, n)
	return nil
}