package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	ldap "github.com/vjeantet/ldapserver"
)

// 検索フィルターから ID や device_id を抽出する正規表現
var serialRegex = regexp.MustCompile(`(?i)serialNumber=(%\{[^}]+\}|[^\(\)\s=]+)`)

func main() {
	ldap.Logger = log.New(os.Stdout, "[LDAPS] ", log.LstdFlags)

	server := ldap.NewServer()

	// ネットワークタイムアウトの設定
	server.ReadTimeout = 30 * time.Second
	server.WriteTimeout = 30 * time.Second

	// 接続ライフサイクルフックの設定
	server.OnNewConnection = func(c net.Conn) error {
		log.Printf("[Connection] New connection from: %s", c.RemoteAddr())
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
	routes.Extended(handleWhoAmI).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")
	routes.Search(handleSearch)

	server.Handle(routes)

	// TLS証明書の読み込み
	cert, err := tls.LoadX509KeyPair("certs/ldap.local.cyphonic.org.pem", "certs/ldap.local.cyphonic.org.key")
	if err != nil {
		log.Fatalf("Failed to load TLS server certificate/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// ca.pem の読み込み
	caCert, err := os.ReadFile("certs/ca.pem")
	if err != nil {
		log.Fatalf("Failed to read CA certificate for mTLS: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("Failed to parse CA certificate from certs/ca.pem")
	}

	// クライアント証明書を「必須」かつ「検証」する設定
	tlsConfig.ClientCAs = caCertPool
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	log.Println("[TLS] Mutual TLS (mTLS) verification STRICTLY enabled.")

	server.TLSConfig = tlsConfig

	// LDAPS 用の TCP リスナーを作成 (ポート 636)
	ln, err := net.Listen("tcp", "127.0.0.1:636")
	if err != nil {
		log.Fatalf("Failed to listen on 127.0.0.1:636: %v", err)
	}

	go func() {
		log.Println("LDAPS Server listening on tls://127.0.0.1:636")
		if err := server.ServeTLS(ln); err != nil {
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

// Simple Bind 用ハンドラ
func handleSimpleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	bindDN := string(r.Name())
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if bindDN == "" || bindDN == "cn=admin,dc=example,dc=org" || bindDN == "myLogin" || bindDN == "uid=myLogin,dc=example,dc=org" {
		log.Printf("[Simple Bind] Success for DN: %s", bindDN)
		// セッション状態に認証済み DN を保存
		m.Client.SetData(bindDN)
		w.Write(res)
		return
	}

	log.Printf("[Simple Bind] Failed for DN: %s", bindDN)
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

// Search ハンドラ
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	filter := r.FilterString()
	baseDN := string(r.BaseObject())

	boundDN, _ := m.Client.GetData().(string)
	log.Printf("[Search] Request received from '%s' - BaseDN: %s, Filter: %s", boundDN, baseDN, filter)

	serialID := ""

	// 1. レイヤー4 (mTLS) クライアント証明書からシリアル番号を取得
	if tlsConn, ok := m.Client.GetConn().(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			serialID = state.PeerCertificates[0].SerialNumber.String()
			log.Printf("[Search] Extracted serialNumber from mTLS Peer Certificate: %s", serialID)
		}
	}

	// 2. mTLS から取得できない場合、検索フィルターからの抽出を試行（フォールバック）
	if serialID == "" {
		matches := serialRegex.FindStringSubmatch(filter)
		if len(matches) > 1 {
			serialID = matches[1]
			log.Printf("[Search] Extracted serialNumber from Search Filter: %s", serialID)
		}
	}

	// クライアントからの非同期キャンセル/中断通知を監視
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

		// 外部 AS 問い合わせ処理のシミュレーション
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
		} else {
			log.Printf("[Search] Certificate not found or invalid for key: %s", serialID)
		}
	}

	done := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(done)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
