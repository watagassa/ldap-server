// Package tlsconfig は mTLS 用の tls.Config を構築する
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

// Load はサーバー証明書・秘密鍵とクライアント検証用 CA を読み込み、
// クライアント証明書を必須とする mTLS 用の tls.Config を返す
func Load(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS server certificate/key: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate for mTLS: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}

	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		ClientCAs:        caCertPool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: verifyConnection,
	}, nil
}

func verifyConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		log.Println("[TLS VerifyConnection Error] Client certificate was not presented.")
		return fmt.Errorf("client certificate required")
	}
	clientCert := cs.PeerCertificates[0]
	log.Printf("[TLS VerifyConnection Success] Subject: %s, Serial: %s",
		clientCert.Subject, clientCert.SerialNumber.String())
	return nil
}

// VersionString は TLS バージョンの数値列挙体を文字列表示に変換する
func VersionString(v uint16) string {
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
