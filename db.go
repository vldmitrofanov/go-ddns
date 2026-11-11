package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS clients (
    id          TEXT PRIMARY KEY,               -- UUID
    name        TEXT NOT NULL UNIQUE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id     TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,         -- sha256(token), plaintext is never stored
    name          TEXT NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    expires_at    DATETIME,                     -- NULL = never
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  DATETIME,
    last_used_ip  TEXT
);
CREATE INDEX IF NOT EXISTS idx_tokens_client ON tokens(client_id);

CREATE TABLE IF NOT EXISTS domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    fqdn        TEXT NOT NULL UNIQUE,           -- e.g. home.example.com (no trailing dot)
    zone_id     TEXT NOT NULL,                  -- Route 53 hosted zone ID
    ttl         INTEGER NOT NULL DEFAULT 60,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_ipv4   TEXT,
    last_ipv6   TEXT,
    updated_at  DATETIME
);
CREATE INDEX IF NOT EXISTS idx_domains_client ON domains(client_id);
`

type DB struct{ *sql.DB }

func openDB(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_foreign_keys=on&_busy_timeout=5000&_journal_mode=WAL"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite: one writer keeps things simple and safe
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &DB{db}, nil
}

// ---------- types ----------

type Client struct {
	ID        string
	Name      string
	Enabled   bool
	CreatedAt time.Time
}

type Token struct {
	ID         int64
	ClientID   string
	ClientName string
	Name       string
	Enabled    bool
	ExpiresAt  sql.NullTime
	CreatedAt  time.Time
	LastUsedAt sql.NullTime
	LastUsedIP sql.NullString
}

type Domain struct {
	ID         int64
	ClientID   string
	ClientName string
	FQDN       string
	ZoneID     string
	TTL        int64
	Enabled    bool
	LastIPv4   sql.NullString
	LastIPv6   sql.NullString
	UpdatedAt  sql.NullTime
}

var errNotFound = errors.New("not found")

// ---------- tokens ----------

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func newTokenString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ddns_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// authenticate returns the client for a valid, enabled, unexpired token.
func (db *DB) authenticate(tok string) (*Client, int64, error) {
	var c Client
	var tokID int64
	err := db.QueryRow(`
		SELECT t.id, c.id, c.name
		FROM tokens t JOIN clients c ON c.id = t.client_id
		WHERE t.token_hash = ?
		  AND t.enabled = 1 AND c.enabled = 1
		  AND (t.expires_at IS NULL OR t.expires_at > CURRENT_TIMESTAMP)`,
		hashToken(tok)).Scan(&tokID, &c.ID, &c.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, errNotFound
	}
	if err != nil {
		return nil, 0, err
	}
	c.Enabled = true
	return &c, tokID, nil
}

func (db *DB) touchToken(id int64, ip string) {
	_, _ = db.Exec(`UPDATE tokens SET last_used_at = CURRENT_TIMESTAMP, last_used_ip = ? WHERE id = ?`, ip, id)
}

func (db *DB) addToken(clientID, name string, ttl time.Duration) (string, int64, error) {
	tok, err := newTokenString()
	if err != nil {
		return "", 0, err
	}
	var exp any
	if ttl > 0 {
		exp = time.Now().UTC().Add(ttl).Format("2006-01-02 15:04:05")
	}
	res, err := db.Exec(`INSERT INTO tokens (client_id, token_hash, name, expires_at) VALUES (?, ?, ?, ?)`,
		clientID, hashToken(tok), name, exp)
	if err != nil {
		return "", 0, err
	}
	id, _ := res.LastInsertId()
	return tok, id, nil
}

func (db *DB) listTokens(clientID string) ([]Token, error) {
	q := `SELECT t.id, t.client_id, c.name, t.name, t.enabled, t.expires_at, t.created_at, t.last_used_at, t.last_used_ip
	      FROM tokens t JOIN clients c ON c.id = t.client_id`
	var args []any
	if clientID != "" {
		q += ` WHERE t.client_id = ?`
		args = append(args, clientID)
	}
	q += ` ORDER BY c.name, t.id`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.ClientID, &t.ClientName, &t.Name, &t.Enabled, &t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt, &t.LastUsedIP); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (db *DB) setTokenEnabled(id int64, on bool) error {
	return mustAffect(db.Exec(`UPDATE tokens SET enabled = ? WHERE id = ?`, on, id))
}

func (db *DB) deleteToken(id int64) error {
	return mustAffect(db.Exec(`DELETE FROM tokens WHERE id = ?`, id))
}

// ---------- clients ----------

func (db *DB) addClient(name string) (string, error) {
	id := uuid.NewString()
	_, err := db.Exec(`INSERT INTO clients (id, name) VALUES (?, ?)`, id, name)
	return id, err
}

// findClient accepts either the UUID or the name.
func (db *DB) findClient(ref string) (*Client, error) {
	var c Client
	err := db.QueryRow(`SELECT id, name, enabled, created_at FROM clients WHERE id = ? OR name = ?`, ref, ref).
		Scan(&c.ID, &c.Name, &c.Enabled, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("client %q: %w", ref, errNotFound)
	}
	return &c, err
}

func (db *DB) listClients() ([]Client, error) {
	rows, err := db.Query(`SELECT id, name, enabled, created_at FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.Name, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (db *DB) setClientEnabled(id string, on bool) error {
	return mustAffect(db.Exec(`UPDATE clients SET enabled = ? WHERE id = ?`, on, id))
}

func (db *DB) deleteClient(id string) error {
	return mustAffect(db.Exec(`DELETE FROM clients WHERE id = ?`, id))
}

// ---------- domains ----------

func normalizeFQDN(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (db *DB) addDomain(clientID, fqdn, zoneID string, ttl int64) error {
	_, err := db.Exec(`INSERT INTO domains (client_id, fqdn, zone_id, ttl) VALUES (?, ?, ?, ?)`,
		clientID, normalizeFQDN(fqdn), zoneID, ttl)
	return err
}

const domainCols = `d.id, d.client_id, c.name, d.fqdn, d.zone_id, d.ttl, d.enabled, d.last_ipv4, d.last_ipv6, d.updated_at`

func scanDomains(rows *sql.Rows) ([]Domain, error) {
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.ClientID, &d.ClientName, &d.FQDN, &d.ZoneID, &d.TTL, &d.Enabled,
			&d.LastIPv4, &d.LastIPv6, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (db *DB) listDomains(clientID string) ([]Domain, error) {
	q := `SELECT ` + domainCols + ` FROM domains d JOIN clients c ON c.id = d.client_id`
	var args []any
	if clientID != "" {
		q += ` WHERE d.client_id = ?`
		args = append(args, clientID)
	}
	rows, err := db.Query(q+` ORDER BY c.name, d.fqdn`, args...)
	if err != nil {
		return nil, err
	}
	return scanDomains(rows)
}

// clientDomains returns the enabled domains of a client. If names is empty,
// all of them; otherwise only the requested ones (error if any isn't owned).
func (db *DB) clientDomains(clientID string, names []string) ([]Domain, error) {
	rows, err := db.Query(`SELECT `+domainCols+` FROM domains d JOIN clients c ON c.id = d.client_id
		WHERE d.client_id = ? AND d.enabled = 1 ORDER BY d.fqdn`, clientID)
	if err != nil {
		return nil, err
	}
	all, err := scanDomains(rows)
	if err != nil || len(names) == 0 {
		return all, err
	}
	byName := make(map[string]Domain, len(all))
	for _, d := range all {
		byName[d.FQDN] = d
	}
	out := make([]Domain, 0, len(names))
	for _, n := range names {
		d, ok := byName[normalizeFQDN(n)]
		if !ok {
			return nil, fmt.Errorf("domain %q: %w", n, errNotFound)
		}
		out = append(out, d)
	}
	return out, nil
}

func (db *DB) setDomainIP(id int64, ipv6 bool, ip string) error {
	col := "last_ipv4"
	if ipv6 {
		col = "last_ipv6"
	}
	_, err := db.Exec(`UPDATE domains SET `+col+` = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, ip, id)
	return err
}

func (db *DB) setDomainEnabled(fqdn string, on bool) error {
	return mustAffect(db.Exec(`UPDATE domains SET enabled = ? WHERE fqdn = ?`, on, normalizeFQDN(fqdn)))
}

func (db *DB) deleteDomain(fqdn string) error {
	return mustAffect(db.Exec(`DELETE FROM domains WHERE fqdn = ?`, normalizeFQDN(fqdn)))
}

func mustAffect(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}
