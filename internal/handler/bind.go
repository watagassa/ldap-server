package handler

import (
	"log"

	ldap "github.com/vjeantet/ldapserver"
)

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
