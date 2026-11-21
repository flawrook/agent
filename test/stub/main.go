// Copyright 2026 Binerals Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// stub stands in for FlawRook's agent API (protocol 1) in the integration run: TLS with its own test CA,
// both routes answered as the contract says, every request written to <out>/requests.jsonl and each
// host's last report to <out>/report-<hostId>.json. Never for production.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxInflated = 20 << 20 // the API's JSON limit, on the inflated body

var hostIDFormat = regexp.MustCompile(`^[0-9a-f]{64}$`)

type stub struct {
	mu     sync.Mutex
	tokens map[string]bool
	out    string
	stored map[string]string // hostId: reportHash
	queue  map[string][]int  // route: statuses to answer first
	log    *os.File
}

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	names := flag.String("names", "stub,localhost", "the certificate's DNS names")
	out := flag.String("out", "/out", "where ca.pem, requests.jsonl and the reports go")
	tokens := flag.String("token", "flra_test", "the accepted tokens, comma-separated")
	releases := flag.String("releases", "", "a directory served over plain HTTP on :8080, as a release for install.sh")
	forward := flag.String("forward", "", "instead of the stub, only forward TCP, listen=target (127.0.0.1:3033=host.docker.internal:3033): an API on the host seen as the agent container's own loopback")
	proxy := flag.String("proxy", "", "instead of the stub, only an HTTP CONNECT proxy on this address (:3128), logging each tunnel's target")
	queue := flag.String("queue", "", "statuses to answer first, as route:status,... (heartbeat:409,report:500)")
	flag.Parse()
	log.SetFlags(0)
	if listen, target, ok := strings.Cut(*forward, "="); ok {
		log.Fatal(forwardTCP(listen, target))
	}
	if *proxy != "" {
		log.Printf("CONNECT proxy on %s", *proxy)
		log.Fatal(http.ListenAndServe(*proxy, http.HandlerFunc(connectProxy)))
	}
	s := &stub{tokens: map[string]bool{}, out: *out, stored: map[string]string{}, queue: map[string][]int{}}
	for _, t := range strings.Split(*tokens, ",") {
		s.tokens[t] = true
	}
	if *releases != "" {
		go func() { log.Fatal(http.ListenAndServe(":8080", http.FileServer(http.Dir(*releases)))) }()
	}
	for _, item := range strings.Split(*queue, ",") {
		if route, status, ok := strings.Cut(item, ":"); ok {
			n, _ := strconv.Atoi(status)
			s.queue[route] = append(s.queue[route], n)
		}
	}
	cert, err := certificate(strings.Split(*names, ","), filepath.Join(*out, "ca.pem"))
	if err != nil {
		log.Fatal(err)
	}
	if s.log, err = os.OpenFile(filepath.Join(*out, "requests.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *addr, Handler: s, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("stub on %s", *addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	route := strings.TrimPrefix(r.URL.Path, "/api/v1/agent/")
	entry := map[string]any{
		"at": time.Now().UTC().Format(time.RFC3339Nano), "route": route, "method": r.Method,
		"userAgent": r.Header.Get("User-Agent"), "protocol": r.Header.Get("FlawRook-Agent-Protocol"),
		"contentEncoding": r.Header.Get("Content-Encoding"), "contentType": r.Header.Get("Content-Type"),
		"token":   tokenHint(r.Header.Get("Authorization")),
		"tokenOk": s.authorized(r),
	}
	status, answer, body := s.answer(r, route, entry)
	entry["status"] = status
	line, _ := json.Marshal(entry)
	_, _ = s.log.Write(append(line, '\n'))
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "5")
	}
	if answer != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(answer)
	} else {
		w.WriteHeader(status)
	}
	if status == http.StatusAccepted {
		var env struct {
			Host struct {
				HostID string `json:"hostId"`
			} `json:"host"`
		}
		_ = json.Unmarshal(body, &env)
		_ = os.WriteFile(filepath.Join(s.out, "report-"+env.Host.HostID+".json"), body, 0o644)
	}
}

type msg map[string]any

func (s *stub) answer(r *http.Request, route string, entry map[string]any) (int, msg, []byte) {
	if r.Method != http.MethodPost || (route != "report" && route != "heartbeat") {
		return http.StatusNotFound, msg{"message": "not found"}, nil
	}
	if !s.authorized(r) {
		return http.StatusUnauthorized, msg{"message": "an agent token is required"}, nil
	}
	if q := s.queue[route]; len(q) > 0 {
		s.queue[route] = q[1:]
		entry["queued"] = true
		return q[0], msg{"message": "queued by the test"}, nil
	}
	if p := r.Header.Get("FlawRook-Agent-Protocol"); p != "1" {
		return http.StatusUpgradeRequired, msg{"message": "protocol " + p + " isn't accepted", "minProtocol": 1}, nil
	}
	var in io.Reader = r.Body
	if route == "report" {
		if r.Header.Get("Content-Encoding") != "gzip" {
			return http.StatusBadRequest, msg{"message": "not gzip"}, nil
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return http.StatusBadRequest, msg{"message": "not gzip"}, nil
		}
		in = zr
	}
	body, err := io.ReadAll(io.LimitReader(in, maxInflated+1))
	if err != nil {
		return http.StatusBadRequest, msg{"message": "not gzip"}, nil
	}
	if len(body) > maxInflated {
		return http.StatusRequestEntityTooLarge, msg{"message": "over 20 MB inflated"}, nil
	}
	entry["bytes"] = len(body)
	var env struct {
		Protocol   *int   `json:"protocol"`
		ReportHash string `json:"reportHash"`
		Host       struct {
			HostID       string            `json:"hostId"`
			HostIDSource string            `json:"hostIdSource"`
			Hostname     string            `json:"hostname"`
			Kernel       string            `json:"kernel"`
			OSRelease    map[string]string `json:"osRelease"`
		} `json:"host"`
		SBOM *struct {
			BOMFormat  string            `json:"bomFormat"`
			Components []json.RawMessage `json:"components"`
		} `json:"sbom"`
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&env); err != nil {
		return http.StatusBadRequest, msg{"message": "not JSON"}, nil
	}
	switch {
	case env.Protocol == nil || *env.Protocol != 1:
		return http.StatusBadRequest, msg{"message": "protocol missing or unlike the header"}, nil
	case !hostIDFormat.MatchString(env.Host.HostID):
		return http.StatusBadRequest, msg{"message": "hostId must be 64 hex characters"}, nil
	case env.ReportHash == "":
		return http.StatusBadRequest, msg{"message": "reportHash missing"}, nil
	}
	entry["hostId"], entry["hostname"], entry["reportHash"] = env.Host.HostID, env.Host.Hostname, env.ReportHash
	if route == "heartbeat" {
		if s.stored[env.Host.HostID] != env.ReportHash {
			return http.StatusConflict, msg{"message": "report required"}, nil
		}
		return http.StatusNoContent, nil, nil
	}
	if env.SBOM == nil || env.SBOM.BOMFormat != "CycloneDX" || env.SBOM.Components == nil {
		return http.StatusBadRequest, msg{"message": "sbom isn't CycloneDX"}, nil
	}
	entry["hostIdSource"], entry["kernel"], entry["os"], entry["components"] = env.Host.HostIDSource, env.Host.Kernel, env.Host.OSRelease["ID"]+" "+env.Host.OSRelease["VERSION_ID"], len(env.SBOM.Components)
	s.stored[env.Host.HostID] = env.ReportHash
	return http.StatusAccepted, msg{"reportHash": env.ReportHash, "url": "https://stub.test/repositories/" + env.Host.HostID[:8]}, body
}

// certificate makes a test CA, writes it to caPath, and returns a server certificate it signed.
func certificate(names []string, caPath string) (tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FlawRook agent stub test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func (s *stub) authorized(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && s.tokens[token]
}

// tokenHint is the token's last 4 characters, for the log.
func tokenHint(authorization string) string {
	if len(authorization) < 4 {
		return ""
	}
	return authorization[len(authorization)-4:]
}

// forwardTCP copies every connection on listen to target, both ways.
func forwardTCP(listen, target string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("forwarding %s to %s", listen, target)
	for {
		in, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer in.Close()
			out, err := net.Dial("tcp", target)
			if err != nil {
				log.Printf("forward: %v", err)
				return
			}
			defer out.Close()
			go func() { _, _ = io.Copy(out, in) }()
			_, _ = io.Copy(in, out)
		}()
	}
}

// connectProxy tunnels a CONNECT to its target, both ways, and logs the target.
func connectProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	log.Printf("CONNECT %s", r.Host)
	out, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	in, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		out.Close()
		return
	}
	_, _ = buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	_ = buf.Flush()
	go func() { _, _ = io.Copy(out, buf); out.Close() }()
	_, _ = io.Copy(in, out)
	in.Close()
}
