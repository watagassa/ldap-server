package handler

import (
	"log"
	"regexp"

	ldap "github.com/vjeantet/ldapserver"

	"test-ldap-server/internal/listener"
)

var serialRegex = regexp.MustCompile(`(?i)serialNumber=(%\{[^}]+\}|[^\(\)\s=]+)`)

func handleSearch(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetSearchRequest()
	filter := r.FilterString()
	baseDN := string(r.BaseObject())

	boundDN, _ := m.Client.GetData().(string)
	log.Printf("[Search] Request received from '%s' - BaseDN: %s, Filter: %s", boundDN, baseDN, filter)

	serialID := ""

	if tlsConn := listener.TLSConn(m.Client.GetConn()); tlsConn != nil {
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
