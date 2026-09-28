package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	ldap "github.com/vjeantet/ldapserver"
)

var serialRegex = regexp.MustCompile(`(?i)serialNumber=(%\{[^}]+\}|[^\(\)\s=]+)`)

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
			remoteAddr, tlsVersionToString(state.Version), state.CipherSuite)

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

// TLS バージョンの数値列挙体を文字列表示に変換するヘルパー関数
func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

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

	routes := ldap.NewRouteMux()
	routes.Bind(handleSimpleBind).AuthenticationChoice("simple")
	routes.Extended(handleWhoAmI).RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Search(handleSearch)
	server.Handle(routes)

	cert, err := tls.LoadX509KeyPair("certs/ldap.local.cyphonic.org.pem", "certs/ldap.local.cyphonic.org.key")
	if err != nil {
		log.Fatalf("Failed to load TLS server certificate/key: %v", err)
	}

	caCert, err := os.ReadFile("certs/radius_chain_ca.pem")
	if err != nil {
		log.Fatalf("Failed to read CA certificate for mTLS: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("Failed to parse CA certificate from certs/radius_chain_ca.pem")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				log.Println("[TLS VerifyConnection Error] Client certificate was not presented.")
				return fmt.Errorf("client certificate required")
			}
			clientCert := cs.PeerCertificates[0]
			log.Printf("[TLS VerifyConnection Success] Subject: %s, Serial: %s",
				clientCert.Subject, clientCert.SerialNumber.String())
			return nil
		},
	}
	

	log.Println("[TLS] Mutual TLS (mTLS) verification STRICTLY enabled.")

	tcpLn, err := net.Listen("tcp", "127.0.0.1:636")
	if err != nil {
		log.Fatalf("Failed to listen on 127.0.0.1:636: %v", err)
	}

	// 標準の tls.Listener を HandshakingListener でラップ
	rawTLSListener := tls.NewListener(tcpLn, tlsConfig)
	mTLSListener := &HandshakingListener{
		Listener:         rawTLSListener,
		HandshakeTimeout: 10 * time.Second,
	}

	go func() {
		log.Println("LDAPS Server listening on tls://127.0.0.1:636")
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

func handleSimpleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	bindDN := string(r.Name())
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if bindDN == "" || bindDN == "cn=admin,dc=example,dc=org" || bindDN == "myLogin" || bindDN == "uid=myLogin,dc=example,dc=org" {
		log.Printf("[Simple Bind] Success for DN: %s", bindDN)
		m.Client.SetData(bindDN)
		w.Write(res)
		return
	}

	log.Printf("[Simple Bind] Failed for DN: %s", bindDN)
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	filter := r.FilterString()
	baseDN := string(r.BaseObject())

	boundDN, _ := m.Client.GetData().(string)
	log.Printf("[Search] Request received from '%s' - BaseDN: %s, Filter: %s", boundDN, baseDN, filter)

	serialID := ""

	var tlsConn *tls.Conn
	if lc, ok := m.Client.GetConn().(*loggingConn); ok {
		tlsConn, _ = lc.Conn.(*tls.Conn)
	} else if c, ok := m.Client.GetConn().(*tls.Conn); ok {
		tlsConn = c
	}

	if tlsConn != nil {
		state := tlsConn.ConnectionState()
		if state.HandshakeComplete && len(state.PeerCertificates) > 0 {
			serialID = state.PeerCertificates[0].SerialNumber.String()
			log.Printf("[Search] Extracted serialNumber from mTLS Peer Certificate: %s", serialID)
		}
	}

	if serialID == "" {
		matches := serialRegex.FindStringSubmatch(filter)
		if len(matches) > 1 {
			serialID = matches[1]
			log.Printf("[Search] Extracted serialNumber from Search Filter: %s", serialID)
		}
	}

	select {
	case <-m.Done:
		log.Printf("[Search] Operation canceled for message ID: %d", m.MessageID())
		res := ldap.NewSearchResultDoneResponse(ldap.LDAPResultCanceled)
		w.Write(res)
		return
	default:
	}

	if serialID != "" {
		log.Printf("[Search] Checking certificate status for key: %s", serialID)
		isValidCert := true
		foundDeviceID := serialID

		if isValidCert {
			log.Printf("[Search] Valid certificate found for key: %s", foundDeviceID)
			userDN := "uid=" + foundDeviceID + "," + baseDN
			if baseDN == "" {
				userDN = "uid=" + foundDeviceID + ",dc=example,dc=org"
			}
			entry := ldap.NewSearchResultEntry(userDN)
			w.Write(entry)
		}
	}

	done := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(done)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
