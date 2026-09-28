package main

import (
	"log"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	ldap "github.com/vjeantet/ldapserver"
)

// 検索フィルターから ID や device_id を抽出する正規表現
// やり方模索中
var serialRegex = regexp.MustCompile(`(?i)serialNumber=(%\{[^}]+\}|[^\(\)\s=]+)`)

// 証明書レコード構造体の定義例
// adapterにマージするときにはちゃんと型揃えたい
// テーブル構造:
// - id: BIGINT (証明書シリアル番号)
// - device_id: VARCHAR(128)
// - status: SMALLINT (有効・失効)
// - expire: DATETIME (有効期限)

func main() {
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	server := ldap.NewServer()

	routes := ldap.NewRouteMux()

	// AuthenticationChoice で Simple Bind と SASL Bind のルーティングを分離
	routes.Bind(handleSimpleBind).AuthenticationChoice("simple")

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

// Search ハンドラ
func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	filter := r.FilterString()
	baseDN := r.BaseObject()

	log.Printf("[Search] Request received - BaseDN: %s, Filter: %s", baseDN, filter)

	// 1. フィルターから証明書IDを抽出
	serialID := ""
	matches := serialRegex.FindStringSubmatch(filter)
	if len(matches) > 1 {
		serialID = matches[1]
	}

	if serialID != "" {
		log.Printf("[Search] Checking certificate status for key: %s", serialID)

		// ----------------------------------------------------------------
		// TODO: データベースへの照会処理を実装する
		//
		// 【想定する検証条件】
		// 1. (device_id = searchKey OR id = searchKey) でレコードを検索
		// 2. status が有効状態 (例: 1) であること
		// 3. expire (有効期限) が現在時刻 (time.Now()) より未来であること
		// ----------------------------------------------------------------

		// DB検証成功時のダミーフラグ (実装時はDBの検索結果に基づいて設定してください)
		isValidCert := true
		foundDeviceID := serialID

		if isValidCert {
			// 有効な証明書が存在する場合 -> SearchResultEntry を生成して返送
			log.Printf("[Search] Valid certificate found for key: %s", foundDeviceID)

			userDN := "uid=" + foundDeviceID + "," + string(baseDN)
			if baseDN == "" {
				userDN = "uid=" + foundDeviceID + ",dc=example,dc=org"
			}

			entry := ldap.NewSearchResultEntry(userDN)

			w.Write(entry)
		} else {
			// 該当なし / 失効 / 期限切れの場合
			log.Printf("[Search] Certificate not found or invalid for key: %s", serialID)
		}
	}

	// 2. 検索完了（SearchResultDone）を送信
	done := ldap.NewSearchResultDoneResponse(ldap.LDAPResultSuccess)
	w.Write(done)
}

func handleWhoAmI(w ldap.ResponseWriter, m *ldap.Message) {
	res := ldap.NewExtendedResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}
