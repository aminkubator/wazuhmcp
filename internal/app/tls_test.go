package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wazuhmcp/internal/config"
)

func TestStartServesTLS(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)

	cfg := &config.Config{
		Addr: "127.0.0.1:0", Token: "a", AdminToken: "b", TLSCert: certFile, TLSKey: keyFile,
		APIURL: "https://x:1", APIUser: "u", APIPassword: "p",
		IndexerURL: "https://x:1", IndexerUser: "u", IndexerPassword: "p",
		MaxPerHour: 10, MaxAgents: 5, PlanTTL: time.Hour, AuditFile: filepath.Join(dir, "a.jsonl"),
	}
	s, err := New(cfg, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(t.Context())

	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://" + s.Addr() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok\n" {
		t.Errorf("healthz over TLS: %q", b)
	}
	if r, err := http.Get("http://" + s.Addr() + "/healthz"); err == nil && r.StatusCode == 200 {
		t.Error("plain HTTP served on a TLS listener")
	}
}

func TestTLSFlagsMustPair(t *testing.T) {
	env := map[string]string{"WAZUHMCP_API_USER": "u", "WAZUHMCP_API_PASSWORD": "p",
		"WAZUHMCP_INDEXER_USER": "u", "WAZUHMCP_INDEXER_PASSWORD": "p"}
	if _, err := config.Parse([]string{"-tls-cert", "c.pem"}, func(k string) string { return env[k] }, io.Discard); err == nil {
		t.Error("-tls-cert without -tls-key accepted")
	}
}
