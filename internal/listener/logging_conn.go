package listener

import (
	"crypto/tls"
	"encoding/hex"
	"log"
	"net"
)

// loggingConn は Read / Write された生データ（TLS復号後）をログ出力するラッパー
type loggingConn struct {
	net.Conn
}

func (c *loggingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		log.Printf("[Packet Received from FreeRadius (%s) - %d bytes]\n%s",
			c.RemoteAddr(), n, hex.Dump(b[:n]))
	}
	return n, err
}

func (c *loggingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		log.Printf("[Packet Sent to FreeRadius (%s) - %d bytes]\n%s",
			c.RemoteAddr(), n, hex.Dump(b[:n]))
	}
	return n, err
}

// TLSConn は conn（loggingConn でラップされている場合はその中身）から *tls.Conn を取り出す。
// TLS 接続でない場合は nil を返す
func TLSConn(conn net.Conn) *tls.Conn {
	if lc, ok := conn.(*loggingConn); ok {
		conn = lc.Conn
	}
	tlsConn, _ := conn.(*tls.Conn)
	return tlsConn
}
