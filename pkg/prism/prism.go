package prism

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/wsuzume/prism/pkg/mode"
)

const ReadHeaderTimeout = 3 * time.Second

func newHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
	}
}

func serveCommandServer(cs CommandServer) error {
	// TODO: refactoring
	var detectErr error
	if cs.Config.Mode == "unix" {
		detectErr = context.Canceled
	} else if cs.Config.Mode == "tcp" {
		detectErr = http.ErrServerClosed
	}
	if err := cs.ListenAndServe(); err != nil && !errors.Is(err, detectErr) {
		log.Println("command server error:", err)
	}
	return nil
}


func serveHTTP(s *http.Server) error {
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func gracefulStop(s1, s2 *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fmt.Println("Shutting down the servers")
	_ = s1.Shutdown(ctx)
	_ = s2.Shutdown(ctx)
}

// コマンドの処理関数
// func commandHandler(cs *CommandSocket, cmd string) string {
// 	switch cmd {
// 	case "ping":
// 		return "pong\n"
// 	case "status":
// 		return "ok\n"
// 	case "reload":
// 		// バッファ詰まり回避のため非ブロッキング送信
// 		select {
// 		case cs.CmdCh <- "reload":
// 			return "reloading\n"
// 		default:
// 			return "busy\n"
// 		}
// 	default:
// 		return "unknown\n"
// 	}
// }

func run(ctx context.Context, addr string, handler http.Handler, tlsConfig *tls.Config) error {
	// cs := NewCommandSocket("/tmp/mydaemon.sock")
	// defer cs.Close()

	// // コマンドソケット起動
	// go func() {
	// 	if err := cs.ListenAndServe(ctx, commandHandler); err != nil && !errors.Is(err, context.Canceled) {
	// 		log.Println("command socket error:", err)
	// 	}
	// }()

	for {
		// ここで s1/s2 を生成して起動
		s1 := newHTTPServer(addr, handler, tlsConfig) // addr を使う
		s2 := newHTTPServer(":8081", handler, tlsConfig)

		errCh := make(chan error, 2)
		fmt.Println("Starting server...")
		go func() { errCh <- serveHTTP(s1) }()
		go func() { errCh <- serveHTTP(s2) }()

		// イベント待ち
		select {
		case <-ctx.Done():
			gracefulStop(s1, s2)
			// 両サーバ終了まで待機（2回受信）
			for i := 0; i < 2; i++ {
				<-errCh
			}
			return ctx.Err()
		case err := <-errCh:
			// どちらかが異常終了したら両方止めてエラー返却
			_ = s1.Close()
			_ = s2.Close()
			// 片方残っている可能性があるので念のためもう一つも受ける
			select {
			case <-errCh:
			case <-time.After(100 * time.Millisecond):
			}
			return err

		// case cmd := <-cs.CmdCh:
		// 	if cmd == "reload" {
		// 		// 優雅に停止してから再生成へ
		// 		gracefulStop(s1, s2)
		// 		for i := 0; i < 2; i++ {
		// 			<-errCh
		// 		}
		// 		// ループ先頭に戻って s1/s2 を再生成・再起動
		// 		continue
		// 	}
		}
	}
}

func Run() {
	if !mode.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	path, err := GetTopPriorityConfigPath()
	if err != nil {
		log.Fatalf("failed to find config file: %v\n", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		log.Fatalf("failed to load config: %v\n", err)
	}
	
	cfg, err = cfg.Normalize()
	if err != nil {
		log.Fatalf("failed to normalize config: %v\n", err)
	}

	fmt.Printf("Config loaded from %s\n", path)
	fmt.Println("======")
	fmt.Print(cfg.String())
	fmt.Println("======")

	// Ctrl+C / SIGTERM を捕捉してコンテキストを閉じる
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	r := gin.New()
	r.Use(gin.Recovery(), gin.Logger())
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello, World!")
	})

	if err := run(ctx, ":8080", r, nil); err != nil && !errors.Is(err, context.Canceled) {
		log.Println("server stopped with error:", err)
	}
}
