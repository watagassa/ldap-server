// Package listener は TLS ハンドシェイクと通信内容のログ出力を行うリスナーを提供する
package listener

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"test-ldap-server/internal/tlsconfig"
)

// HandshakingListener は Accept 時に TLS ハンドシェイクを実行し、ログを記録するリスナー
type HandshakingListener struct {
	net.Listener
	HandshakeTimeout time.Duration
}

func (l *HandshakingListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			return conn, nil
		}

		remoteAddr := conn.RemoteAddr().String()
		log.Printf("[TLS Phase 1] Incoming connection from %s. Starting TLS Handshake...", remoteAddr)

		// ハンドシェイク無応答による無制限ハングアップを防止するためのデッドライン設定
		if l.HandshakeTimeout > 0 {
			_ = tlsConn.SetDeadline(time.Now().Add(l.HandshakeTimeout))
		}

		// 明示的に TLS ハンドシェイクを実行
		if err := tlsConn.Handshake(); err != nil {
			// クライアント側が証明書を出さない等のエラーログを出力し、接続を閉じる
			log.Printf("[TLS Error] Handshake failed from %s: %v", remoteAddr, err)
			_ = tlsConn.Close()
			// 単一クライアントのエラーで server.Serve() を落とさないため、次の接続待ちへループ
			continue
		}

		// ハンドシェイク成功後の詳細情報取得とログ出力
		state := tlsConn.ConnectionState()
		log.Printf("[TLS Phase 2] Handshake Success with %s | Protocol: %s, CipherSuite: 0x%04x",
			remoteAddr, tlsconfig.VersionString(state.Version), state.CipherSuite)

		if len(state.PeerCertificates) > 0 {
			clientCert := state.PeerCertificates[0]
			log.Printf("[TLS Auth] Client Certificate Presented by %s | Subject: %s | Serial: %s | Issuer: %s",
				remoteAddr, clientCert.Subject, clientCert.SerialNumber.String(), clientCert.Issuer)
		} else {
			log.Printf("[TLS Auth Warning] Handshake completed with %s but NO Client Certificate presented.", remoteAddr)
		}

		// ハンドシェイク成功後、タイムアウト制限を解除
		_ = tlsConn.SetDeadline(time.Time{})

		// TLS 復号後のパケットをキャプチャするために loggingConn でラップして返す
		return &loggingConn{Conn: tlsConn}, nil
	}
}
