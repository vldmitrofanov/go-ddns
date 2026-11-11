package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type Server struct {
	cfg *Config
	db  *DB
	bl  *Blacklist
	dns DNSUpdater

	updMu sync.Mutex // serialise updates: avoids racing duplicate Route 53 calls
}

type result struct {
	Domain string `json:"domain"`
	Status string `json:"status"` // updated | unchanged | error
	Error  string `json:"error,omitempty"`
}

type updateResponse struct {
	Client   string   `json:"client"`
	IP       string   `json:"ip"`
	Type     string   `json:"type"`
	ChangeID []string `json:"change_id,omitempty"`
	Results  []result `json:"results"`
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/update", s.handleUpdate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Anything else is a scanner poking around (/wp-login.php, /.env, ...)
		s.fail(w, r, http.StatusNotFound, "unknown path "+trunc(r.URL.Path, 80))
	})
	return s.guard(mux)
}

// guard drops banned clients before any handler runs.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if s.bl.IsBanned(ip) {
			dropConn(w)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.fail(w, r, http.StatusMethodNotAllowed, "method "+r.Method)
		return
	}

	tok, ok := bearer(r)
	if !ok {
		s.fail(w, r, http.StatusUnauthorized, "missing bearer token")
		return
	}
	client, tokID, err := s.db.authenticate(tok)
	if errors.Is(err, errNotFound) {
		s.fail(w, r, http.StatusUnauthorized, "invalid token")
		return
	}
	if err != nil {
		log.Printf("auth db error: %v", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.bl.Succeed(ip)
	s.db.touchToken(tokID, ip.String())

	// domain=home.example.com | domain=a.example.com,b.example.com | domain=all | (absent) = all
	var names []string
	if raw := strings.TrimSpace(r.FormValue("domain")); raw != "" && raw != "all" {
		for _, n := range strings.Split(raw, ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if len(names) > 50 || len(raw) > 2048 {
			httpError(w, http.StatusBadRequest, "too many domains")
			return
		}
	}

	domains, err := s.db.clientDomains(client.ID, names)
	if errors.Is(err, errNotFound) {
		httpError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		log.Printf("domains db error: %v", err)
		httpError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(domains) == 0 {
		httpError(w, http.StatusNotFound, "no domains configured for this client")
		return
	}

	resp := s.update(r.Context(), client, ip, domains)
	code := http.StatusOK
	for _, res := range resp.Results {
		if res.Status == "error" {
			code = http.StatusBadGateway
		}
	}
	writeJSON(w, code, resp)
}

func (s *Server) update(ctx context.Context, client *Client, ip netip.Addr, domains []Domain) updateResponse {
	isV6 := ip.Is6()
	rtype := "A"
	if isV6 {
		rtype = "AAAA"
	}
	ipStr := ip.String()
	resp := updateResponse{Client: client.Name, IP: ipStr, Type: rtype}

	s.updMu.Lock()
	defer s.updMu.Unlock()

	// Group the domains that actually changed by hosted zone: one API call per zone.
	byZone := map[string][]Domain{}
	var zones []string
	status := map[string]result{}
	for _, d := range domains {
		last := d.LastIPv4
		if isV6 {
			last = d.LastIPv6
		}
		if last.Valid && last.String == ipStr {
			status[d.FQDN] = result{Domain: d.FQDN, Status: "unchanged"}
			continue
		}
		if _, ok := byZone[d.ZoneID]; !ok {
			zones = append(zones, d.ZoneID)
		}
		byZone[d.ZoneID] = append(byZone[d.ZoneID], d)
	}

	for _, z := range zones {
		recs := byZone[z]
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		changeID, err := s.dns.Upsert(cctx, z, rtype, ipStr, recs)
		cancel()
		for _, d := range recs {
			if err != nil {
				log.Printf("update FAIL client=%s %s %s -> %s: %v", client.Name, d.FQDN, rtype, ipStr, err)
				status[d.FQDN] = result{Domain: d.FQDN, Status: "error", Error: "route53 update failed"}
				continue
			}
			if err := s.db.setDomainIP(d.ID, isV6, ipStr); err != nil {
				log.Printf("db: save ip for %s: %v", d.FQDN, err)
			}
			log.Printf("update OK client=%s %s %s -> %s (%s)", client.Name, d.FQDN, rtype, ipStr, changeID)
			status[d.FQDN] = result{Domain: d.FQDN, Status: "updated"}
		}
		if err == nil {
			resp.ChangeID = append(resp.ChangeID, changeID)
		}
	}

	for _, d := range domains { // keep request order
		resp.Results = append(resp.Results, status[d.FQDN])
	}
	return resp
}

// fail answers with an error and counts it towards an auto-ban.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, reason string) {
	ip := s.clientIP(r)
	log.Printf("reject %s %s %s: %s", ip, r.Method, trunc(r.URL.RequestURI(), 120), reason)
	if s.bl.Fail(ip, reason) {
		dropConn(w)
		return
	}
	httpError(w, code, http.StatusText(code))
}

// clientIP returns the TCP peer, or the forwarded client if the peer is a trusted proxy.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	peer := ap.Addr().Unmap()
	if len(s.cfg.trustedProxies) == 0 || !inPrefixes(peer, s.cfg.trustedProxies) {
		return peer
	}
	// Walk X-Forwarded-For right-to-left, skipping our own proxies.
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		parts := strings.Split(strings.Join(xff, ","), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				break
			}
			a = a.Unmap()
			if !inPrefixes(a, s.cfg.trustedProxies) {
				return a
			}
		}
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return a.Unmap()
	}
	return peer
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "bearer "
	if len(h) <= len(p) || !strings.EqualFold(h[:len(p)], p) {
		return "", false
	}
	t := strings.TrimSpace(h[len(p):])
	return t, t != "" && len(t) < 256
}

// dropConn closes the connection without a response — scanners get nothing.
func dropConn(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, err := hj.Hijack(); err == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // RST instead of FIN
			}
			c.Close()
			return
		}
	}
	w.WriteHeader(http.StatusForbidden)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// banListener refuses banned peers at accept() time, before TLS or HTTP
// parsing. Peers that are trusted proxies are let through (their real
// client is checked by guard()).
type banListener struct {
	net.Listener
	s *Server
}

func (l banListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
			ip := ap.Addr().Unmap()
			if !inPrefixes(ip, l.s.cfg.trustedProxies) && l.s.bl.IsBanned(ip) {
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.SetLinger(0)
				}
				c.Close()
				continue
			}
		}
		return c, nil
	}
}
