package main

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	ldap "github.com/vjeantet/ldapserver"

	"test-ldap-server/internal/handler"
	"test-ldap-server/internal/listener"
	"test-ldap-server/internal/tlsconfig"
)

const (
	listenAddr = "127.0.0.1:636"
	certFile   = "certs/ldap.local.cyphonic.org.pem"
	keyFile    = "certs/ldap.local.cyphonic.org.key"
	caFile     = "certs/radius_chain_ca.pem"
)

func main() {
	ldap.Logger = log.New(os.Stdout, "[LDAPS] ", log.LstdFlags)

	server := ldap.NewServer()
	server.ReadTimeout = 30 * time.Second
	server.WriteTimeout = 30 * time.Second

	server.OnNewConnection = func(c net.Conn) error {
		log.Printf("[Connection] New TCP connection established from: %s", c.RemoteAddr())
		return nil
	}

	server.OnClientClose = func(conn net.Conn, data any) {
		boundDN, _ := data.(string)
		if boundDN == "" {
			boundDN = "Anonymous"
		}
		log.Printf("[Connection] Session closed for %s (Bound DN: %s)", conn.RemoteAddr(), boundDN)
	}

	server.Handle(handler.NewRouteMux())

	tlsConfig, err := tlsconfig.Load(certFile, keyFile, caFile)
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Println("[TLS] Mutual TLS (mTLS) verification STRICTLY enabled.")

	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}

	// 標準の tls.Listener を HandshakingListener でラップ
	rawTLSListener := tls.NewListener(tcpLn, tlsConfig)
	mTLSListener := &listener.HandshakingListener{
		Listener:         rawTLSListener,
		HandshakeTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("LDAPS Server listening on tls://%s", listenAddr)
		if err := server.Serve(mTLSListener); err != nil {
			log.Fatalf("LDAPS Server serve error: %v", err)
		}
	}()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	log.Println("Shutting down LDAPS Server...")
	server.Stop()
}
