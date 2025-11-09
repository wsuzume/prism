package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

type CommandSocket struct {
	Path  string
	CmdCh chan string

	listener net.Listener
}

func NewCommandSocket(path string) *CommandSocket {
	return &CommandSocket{
		Path:  path,
		CmdCh: make(chan string, 1),
	}
}

func (c *CommandSocket) ListenAndServe(ctx context.Context, handler func(*CommandSocket, string) string) error {
	// 古いソケットの掃除（存在しない場合は無視）
	_ = os.Remove(c.Path)

	ln, err := net.Listen("unix", c.Path)
	if err != nil {
		return fmt.Errorf("listen unix %q: %w", c.Path, err)
	}
	c.listener = ln

	// 作成後に権限設定
	_ = os.Chmod(c.Path, 0o600)

	// ctx キャンセルでクリーンアップ
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			// 明示的に閉じられた場合は正常終了
			if err == net.ErrClosed {
				return nil
			}
			// コンテキスト終了なら正常終了
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			// 一過性エラーなら継続
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			// それ以外はエラーを返す
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		go c.handleConn(conn, handler)
	}
}

func (c *CommandSocket) Close() error {
	// 重複呼び出しに対して安全
	if c.listener != nil {
		_ = c.listener.Close()
	}
	_ = os.Remove(c.Path)
	return nil
}

func (c *CommandSocket) handleConn(conn net.Conn, handler func(*CommandSocket, string) string) {
	defer conn.Close()

	const idle = 30 * time.Second
	// 最初の期限を設定
	_ = conn.SetReadDeadline(time.Now().Add(idle))

	sc := bufio.NewScanner(conn)
	// デフォルト64KiB→最大1MiBへ拡張
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	for sc.Scan() {
		// 次の読み取りに備えて期限を更新（アイドルタイムアウト）
		_ = conn.SetReadDeadline(time.Now().Add(idle))

		cmd := sc.Text()

		// コマンド処理関数を呼び出す
		resp := handler(c, cmd)
		if resp != "" {
			_, _ = conn.Write([]byte(resp))
		}
	}

	// タイムアウト/その他エラーを判定
	if err := sc.Err(); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			// タイムアウト通知（任意）
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			_, _ = conn.Write([]byte("timeout\n"))
			return
		}
		// 必要ならログに出す
		// log.Printf("command socket read error: %v", err)
	}
	// err == nil の場合は EOF（クライアントが閉じた）
}
