package main

import (
	"bufio"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Blacklist holds banned IPs/CIDRs loaded from every list file in a directory,
// plus a failure counter that auto-bans repeat offenders into AutoFile.
//
// File format: one IP or CIDR per line; '#' starts a comment.
type Blacklist struct {
	cfg BlacklistConfig

	mu       sync.RWMutex
	single   map[netip.Addr]struct{} // exact IPs: O(1) lookup
	prefixes []netip.Prefix          // real ranges
	sig      string                  // change detection for reload

	fmu      sync.Mutex
	failures map[netip.Addr]*failRec
}

type failRec struct {
	count int
	first time.Time
}

func newBlacklist(cfg BlacklistConfig) (*Blacklist, error) {
	b := &Blacklist{cfg: cfg, failures: map[netip.Addr]*failRec{}}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, err
	}
	if err := b.reload(); err != nil {
		return nil, err
	}
	return b, nil
}

func isListFile(name string) bool {
	switch filepath.Ext(name) {
	case ".txt", ".list", ".conf":
		return true
	}
	return false
}

func (b *Blacklist) files() ([]string, string, error) {
	entries, err := os.ReadDir(b.cfg.Dir)
	if err != nil {
		return nil, "", err
	}
	var files []string
	var sig strings.Builder
	for _, e := range entries {
		if e.IsDir() || !isListFile(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		p := filepath.Join(b.cfg.Dir, e.Name())
		files = append(files, p)
		fmt.Fprintf(&sig, "%s|%d|%d;", p, info.Size(), info.ModTime().UnixNano())
	}
	if b.cfg.AutoFile != "" && filepath.Dir(b.cfg.AutoFile) != filepath.Clean(b.cfg.Dir) {
		if info, err := os.Stat(b.cfg.AutoFile); err == nil {
			files = append(files, b.cfg.AutoFile)
			fmt.Fprintf(&sig, "%s|%d|%d;", b.cfg.AutoFile, info.Size(), info.ModTime().UnixNano())
		}
	}
	sort.Strings(files)
	return files, sig.String(), nil
}

func (b *Blacklist) reload() error {
	files, sig, err := b.files()
	if err != nil {
		return err
	}
	single := map[netip.Addr]struct{}{}
	var prefixes []netip.Prefix
	for _, f := range files {
		entries, err := readListFile(f)
		if err != nil {
			log.Printf("blacklist: %s: %v", f, err)
			continue
		}
		for _, p := range entries {
			if p.IsSingleIP() {
				single[p.Addr()] = struct{}{}
			} else {
				prefixes = append(prefixes, p)
			}
		}
	}
	b.mu.Lock()
	b.single, b.prefixes, b.sig = single, prefixes, sig
	b.mu.Unlock()
	log.Printf("blacklist: loaded %d IPs + %d ranges from %d file(s)", len(single), len(prefixes), len(files))
	return nil
}

func readListFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := parsePrefix(strings.Fields(line)[0])
		if err != nil {
			log.Printf("blacklist: %s:%d: %v", path, n, err)
			continue
		}
		out = append(out, p)
	}
	return out, sc.Err()
}

// watch re-reads the lists whenever a file changes (so CLI bans and manual
// edits apply without a restart). SIGHUP also triggers reload, see main.go.
func (b *Blacklist) watch(stop <-chan struct{}) {
	iv := b.cfg.PollInterval.Duration
	if iv <= 0 {
		iv = 10 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_, sig, err := b.files()
			b.mu.RLock()
			changed := err == nil && sig != b.sig
			b.mu.RUnlock()
			if changed {
				_ = b.reload()
			}
			b.gcFailures()
		}
	}
}

func (b *Blacklist) IsBanned(ip netip.Addr) bool {
	ip = ip.Unmap()
	if inPrefixes(ip, b.cfg.whitelist) {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if _, ok := b.single[ip]; ok {
		return true
	}
	return inPrefixes(ip, b.prefixes)
}

// Fail records a bad request; returns true if this caused a ban.
func (b *Blacklist) Fail(ip netip.Addr, reason string) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || inPrefixes(ip, b.cfg.whitelist) {
		return false
	}
	now := time.Now()
	b.fmu.Lock()
	r := b.failures[ip]
	if r == nil || now.Sub(r.first) > b.cfg.Window.Duration {
		r = &failRec{first: now}
		b.failures[ip] = r
	}
	r.count++
	hit := r.count >= b.cfg.MaxFailures
	if hit {
		delete(b.failures, ip)
	}
	b.fmu.Unlock()

	if !hit {
		return false
	}
	if err := b.Ban(ip.String(), fmt.Sprintf("auto: %d failures, last: %s", b.cfg.MaxFailures, reason)); err != nil {
		log.Printf("blacklist: ban %s: %v", ip, err)
	}
	return true
}

func (b *Blacklist) Succeed(ip netip.Addr) {
	b.fmu.Lock()
	delete(b.failures, ip.Unmap())
	b.fmu.Unlock()
}

func (b *Blacklist) gcFailures() {
	cutoff := time.Now().Add(-b.cfg.Window.Duration)
	b.fmu.Lock()
	for ip, r := range b.failures {
		if r.first.Before(cutoff) {
			delete(b.failures, ip)
		}
	}
	b.fmu.Unlock()
}

// Ban appends an entry to AutoFile and applies it in memory immediately.
func (b *Blacklist) Ban(entry, comment string) error {
	p, err := parsePrefix(entry)
	if err != nil {
		return err
	}
	if err := appendBan(b.cfg.AutoFile, p, comment); err != nil {
		return err
	}
	b.mu.Lock()
	if p.IsSingleIP() {
		b.single[p.Addr()] = struct{}{}
	} else {
		b.prefixes = append(b.prefixes, p)
	}
	b.mu.Unlock()
	log.Printf("blacklist: BANNED %s (%s)", p, comment)
	return nil
}

func formatEntry(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func appendBan(file string, p netip.Prefix, comment string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\t# %s %s\n", formatEntry(p), time.Now().UTC().Format(time.RFC3339), comment)
	return err
}

// removeBan deletes an entry from every list file in the directory that
// contains it exactly. Returns the files that were changed.
func removeBan(cfg BlacklistConfig, entry string) ([]string, error) {
	target, err := parsePrefix(entry)
	if err != nil {
		return nil, err
	}
	b := &Blacklist{cfg: cfg}
	files, _, err := b.files()
	if err != nil {
		return nil, err
	}
	var changed []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return changed, err
		}
		lines := strings.SplitAfter(string(data), "\n")
		var keep strings.Builder
		hit := false
		for _, l := range lines {
			body := l
			if i := strings.IndexByte(body, '#'); i >= 0 {
				body = body[:i]
			}
			if fs := strings.Fields(body); len(fs) > 0 {
				if p, err := parsePrefix(fs[0]); err == nil && p == target {
					hit = true
					continue
				}
			}
			keep.WriteString(l)
		}
		if hit {
			if err := os.WriteFile(f, []byte(keep.String()), 0o640); err != nil {
				return changed, err
			}
			changed = append(changed, f)
		}
	}
	return changed, nil
}
