package main

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

func main() {
	// LDAP ロガーの設定
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	// LDAP サーバのインスタンス化
	server := ldap.NewServer()

	// ルーティングの設定
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch) // FreeRADIUSとの連携に必要なSearchハンドラを追加
	server.Handle(routes)

	// ポート 10389 で非同期リスン開始
	go func() {
		if err := server.ListenAndServe("127.0.0.1:10389"); err != nil {
			log.Fatalf("LDAP Server listen error: %v", err)
		}
	}()

	log.Println("LDAP Server listening on 127.0.0.1:10389")

	// シグナル受信時のグレースフルシャットダウン
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Stop()
}

// handleBind はバインド要求を検証します
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	bindDN := string(r.Name())
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	// 1. 初期検索用の匿名バインドまたは管理者バインドの許可
	if bindDN == "" || bindDN == "cn=admin,dc=example,dc=org" {
		w.Write(res)
		return
	}

	// 2. ユーザーバインドの検証
	// FreeRADIUSは検索結果で返されたDN（"uid=myLogin,dc=example,dc=org"）または生のユーザー名でバインドします
	if bindDN == "myLogin" || bindDN == "uid=myLogin,dc=example,dc=org" {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", bindDN, string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}

// handleSearch はFreeRADIUSからのユーザー検索リクエストに応答します
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	filter := r.FilterString()
	log.Printf("Search request received - BaseDN: %s, Filter: %s", r.BaseObject(), filter)

	// 検索フィルタに "myLogin" が含まれているか（または全件検索か）を判定
	if strings.Contains(filter, "myLogin") || filter == "(objectClass=*)" {
		// 該当ユーザーの SearchResultEntry を生成
		userDN := "uid=myLogin,dc=example,dc=org"
		entry := ldap.NewSearchResultEntry(userDN)
		entry.AddAttribute("objectClass", "posixAccount", "top", "person")
		entry.AddAttribute("uid", "myLogin")
		entry.AddAttribute("cn", "myLogin")

		// 検索結果エントリを送信
		w.Write(entry)
	}

	// 検索完了応答メッセージを送信 (LDAPResultSuccess = 0)
	done := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(done)
}
