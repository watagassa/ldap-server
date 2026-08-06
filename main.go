package main

import (
	"crypto/tls"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	server := ldap.NewServer()

	routes := ldap.NewRouteMux()

	// AuthenticationChoice で Simple Bind と SASL Bind のルーティングを分離
	routes.Bind(handleSimpleBind).AuthenticationChoice("simple")
	routes.Bind(handleSaslBind).AuthenticationChoice("sasl")

	routes.Extended(handleWhoAmI).
		RequestName(ldap.NoticeOfWhoAmI).Label("Ext - WhoAmI")

	routes.Search(handleSearch)
	server.Handle(routes)

	go func() {
		if err := server.ListenAndServe("127.0.0.1:10389"); err != nil {
			log.Fatalf("LDAP Server listen error: %v", err)
		}
	}()

	log.Println("LDAP Server listening on 127.0.0.1:10389")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

// Simple Bind 用ハンドラ
func handleSimpleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	bindDN := string(r.Name())
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if bindDN == "" || bindDN == "cn=admin,dc=example,dc=org" || bindDN == "myLogin" || bindDN == "uid=myLogin,dc=example,dc=org" {
		log.Printf("[Simple Bind] Success for DN: %s", bindDN)
		w.Write(res)
		return
	}

	log.Printf("[Simple Bind] Failed for DN: %s", bindDN)
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

// SASL Bind 用ハンドラ　go get github.com/vjeantet/ldapserver@masterでないとSASL EXTERNALが使えないので注意
func handleSaslBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	mech := string(r.AuthenticationSasl().Mechanism())

	// EXTERNAL メカニズム以外の拒否
	if strings.ToUpper(mech) != "EXTERNAL" {
		res := ldap.NewBindResponse(ldap.LDAPResultAuthMethodNotSupported)
		res.SetDiagnosticMessage("SASL mechanism not supported: " + mech)
		w.Write(res)
		return
	}

	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	// TLS 接続経由の場合、クライアント証明書情報を取得して検証
	if tlsConn, ok := m.Client.GetConn().(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			log.Printf("[SASL EXTERNAL] Verified Peer Certificate Subject: %s", cert.Subject.String())
			w.Write(res)
			return
		}
	}

	// クライアント証明書が見つからない場合の処理（必要に応じて失敗応答に変更可能）
	log.Println("[SASL EXTERNAL] Accepted without peer certificate check")
	w.Write(res)
}

// Search ハンドラ
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	filter := r.FilterString()
	log.Printf("Search request received - BaseDN: %s, Filter: %s", r.BaseObject(), filter)

	if strings.Contains(filter, "myLogin") || filter == "(objectClass=*)" {
		userDN := "uid=myLogin,dc=example,dc=org"
		entry := ldap.NewSearchResultEntry(userDN)
		entry.AddAttribute("objectClass", "posixAccount", "top", "person")
		entry.AddAttribute("uid", "myLogin")
		entry.AddAttribute("cn", "myLogin")

		w.Write(entry)
	}

	done := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(done)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
