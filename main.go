package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"
)

const usage = `go-ddns — dynamic DNS for AWS Route 53

Usage:
  go-ddns [-c config.toml] <command> [args]

Server:
  serve                                   run the HTTP server

Clients:
  client add <name>                       create a client (prints its UUID)
  client list
  client enable|disable <id|name>
  client delete <id|name>                 also deletes its tokens and domains

Tokens (the plaintext token is shown ONCE, only its sha256 is stored):
  token add <client> [-name label] [-expires 8760h]
  token list [client]
  token enable|disable|delete <token-id>

Domains:
  domain add <client> <fqdn> [-zone ZONEID] [-ttl 60]   (zone auto-detected if omitted)
  domain list [client]
  domain enable|disable|delete <fqdn>

Blacklist:
  ban <ip|cidr> [comment]                 append to the auto blacklist file
  unban <ip|cidr>                         remove from every blacklist file
  bans                                    show all loaded entries

Config path: -c flag, else $GO_DDNS_CONFIG, else ` + defaultConfigPath + `
`

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	fs := flag.NewFlagSet("go-ddns", flag.ExitOnError)
	cfgPath := fs.String("c", configPathFromEnv(), "config file")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	_ = fs.Parse(os.Args[1:])
	args := fs.Args()
	if len(args) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}

	if args[0] == "serve" {
		fatal(serve(cfg))
		return
	}
	if err := runCLI(cfg, args); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(cfg *Config) error {
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	bl, err := newBlacklist(cfg.Blacklist)
	if err != nil {
		return fmt.Errorf("blacklist: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var dns DNSUpdater = dryRunUpdater{}
	if !cfg.DryRun {
		if dns, err = newRoute53(ctx, cfg.AWS); err != nil {
			return fmt.Errorf("aws: %w", err)
		}
	} else {
		log.Printf("DRY RUN: Route 53 will not be touched")
	}

	s := &Server{cfg: cfg, db: db, bl: bl, dns: dns}

	stopWatch := make(chan struct{})
	go bl.watch(stopWatch)
	defer close(stopWatch)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Printf("SIGHUP: reloading blacklist")
			_ = bl.reload()
		}
	}()

	addr := net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(os.Stderr, "http: ", log.LstdFlags),
	}

	errc := make(chan error, 1)
	go func() {
		bln := banListener{Listener: ln, s: s}
		if cfg.TLS.CertFile != "" {
			log.Printf("listening on https://%s", addr)
			errc <- srv.ServeTLS(bln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			log.Printf("listening on http://%s  (put it behind TLS — tokens travel in headers!)", addr)
			errc <- srv.Serve(bln)
		}
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Printf("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
	return nil
}

// ------------------------------------------------------------------ CLI

func runCLI(cfg *Config, args []string) error {
	switch args[0] {
	case "ban":
		if len(args) < 2 {
			return errors.New("usage: ban <ip|cidr> [comment]")
		}
		p, err := parsePrefix(args[1])
		if err != nil {
			return err
		}
		comment := "manual"
		if len(args) > 2 {
			comment = "manual: " + joinArgs(args[2:])
		}
		if err := appendBan(cfg.Blacklist.AutoFile, p, comment); err != nil {
			return err
		}
		fmt.Printf("banned %s (running server picks it up within %s)\n", formatEntry(p), cfg.Blacklist.PollInterval.Duration)
		return nil
	case "unban":
		if len(args) < 2 {
			return errors.New("usage: unban <ip|cidr>")
		}
		files, err := removeBan(cfg.Blacklist, args[1])
		if err != nil {
			return err
		}
		if len(files) == 0 {
			return fmt.Errorf("%s not found in any blacklist file (a wider CIDR may still cover it)", args[1])
		}
		fmt.Printf("removed %s from %v\n", args[1], files)
		return nil
	case "bans":
		b := &Blacklist{cfg: cfg.Blacklist}
		files, _, err := b.files()
		if err != nil {
			return err
		}
		for _, f := range files {
			es, err := readListFile(f)
			if err != nil {
				return err
			}
			fmt.Printf("# %s (%d)\n", f, len(es))
			for _, e := range es {
				fmt.Println(formatEntry(e))
			}
		}
		return nil
	}

	db, err := openDB(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if len(args) < 2 {
		return fmt.Errorf("unknown or incomplete command %q (run without args for help)", args[0])
	}
	cmd, sub, rest := args[0], args[1], args[2:]
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	defer tw.Flush()

	switch cmd + " " + sub {
	// ---- clients
	case "client add":
		if len(rest) != 1 {
			return errors.New("usage: client add <name>")
		}
		id, err := db.addClient(rest[0])
		if err != nil {
			return err
		}
		fmt.Println(id)
	case "client list":
		cs, err := db.listClients()
		if err != nil {
			return err
		}
		fmt.Fprintln(tw, "ID\tNAME\tENABLED\tCREATED")
		for _, c := range cs {
			fmt.Fprintf(tw, "%s\t%s\t%v\t%s\n", c.ID, c.Name, c.Enabled, c.CreatedAt.Format(time.DateTime))
		}
	case "client enable", "client disable", "client delete":
		if len(rest) != 1 {
			return fmt.Errorf("usage: client %s <id|name>", sub)
		}
		c, err := db.findClient(rest[0])
		if err != nil {
			return err
		}
		if sub == "delete" {
			err = db.deleteClient(c.ID)
		} else {
			err = db.setClientEnabled(c.ID, sub == "enable")
		}
		if err != nil {
			return err
		}
		fmt.Printf("client %s: %sd\n", c.Name, sub)

	// ---- tokens
	case "token add":
		f := flag.NewFlagSet("token add", flag.ExitOnError)
		name := f.String("name", "", "label")
		exp := f.Duration("expires", 0, "lifetime, e.g. 8760h (0 = never)")
		ref, fargs := splitPositional(rest)
		_ = f.Parse(fargs)
		if ref == "" {
			return errors.New("usage: token add <client> [-name label] [-expires 8760h]")
		}
		c, err := db.findClient(ref)
		if err != nil {
			return err
		}
		tok, id, err := db.addToken(c.ID, *name, *exp)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "token #%d for client %s — store it now, it cannot be shown again:\n", id, c.Name)
		fmt.Println(tok)
	case "token list":
		var cid string
		if len(rest) > 0 {
			c, err := db.findClient(rest[0])
			if err != nil {
				return err
			}
			cid = c.ID
		}
		ts, err := db.listTokens(cid)
		if err != nil {
			return err
		}
		fmt.Fprintln(tw, "ID\tCLIENT\tNAME\tENABLED\tEXPIRES\tLAST USED\tLAST IP")
		for _, t := range ts {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%v\t%s\t%s\t%s\n", t.ID, t.ClientName, t.Name, t.Enabled,
				nt(t.ExpiresAt, "never"), nt(t.LastUsedAt, "-"), ns(t.LastUsedIP))
		}
	case "token enable", "token disable", "token delete":
		if len(rest) != 1 {
			return fmt.Errorf("usage: token %s <token-id>", sub)
		}
		id, err := strconv.ParseInt(rest[0], 10, 64)
		if err != nil {
			return fmt.Errorf("token id must be a number")
		}
		if sub == "delete" {
			err = db.deleteToken(id)
		} else {
			err = db.setTokenEnabled(id, sub == "enable")
		}
		if err != nil {
			return err
		}
		fmt.Printf("token #%d: %sd\n", id, sub)

	// ---- domains
	case "domain add":
		f := flag.NewFlagSet("domain add", flag.ExitOnError)
		zone := f.String("zone", "", "Route 53 hosted zone ID (auto-detect if empty)")
		ttl := f.Int64("ttl", cfg.AWS.DefaultTTL, "record TTL")
		pos, fargs := splitPositionals(rest, 2)
		_ = f.Parse(fargs)
		if len(pos) != 2 {
			return errors.New("usage: domain add <client> <fqdn> [-zone ID] [-ttl 60]")
		}
		c, err := db.findClient(pos[0])
		if err != nil {
			return err
		}
		fqdn := normalizeFQDN(pos[1])
		if *zone == "" {
			r, err := newRoute53(context.Background(), cfg.AWS)
			if err != nil {
				return err
			}
			if *zone, err = r.FindZone(context.Background(), fqdn); err != nil {
				return fmt.Errorf("zone lookup: %w (pass -zone explicitly)", err)
			}
			fmt.Fprintf(os.Stderr, "found hosted zone %s\n", *zone)
		}
		if err := db.addDomain(c.ID, fqdn, *zone, *ttl); err != nil {
			return err
		}
		fmt.Printf("domain %s -> client %s (zone %s, ttl %d)\n", fqdn, c.Name, *zone, *ttl)
	case "domain list":
		var cid string
		if len(rest) > 0 {
			c, err := db.findClient(rest[0])
			if err != nil {
				return err
			}
			cid = c.ID
		}
		ds, err := db.listDomains(cid)
		if err != nil {
			return err
		}
		fmt.Fprintln(tw, "FQDN\tCLIENT\tZONE\tTTL\tENABLED\tIPv4\tIPv6\tUPDATED")
		for _, d := range ds {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%v\t%s\t%s\t%s\n", d.FQDN, d.ClientName, d.ZoneID, d.TTL, d.Enabled,
				ns(d.LastIPv4), ns(d.LastIPv6), nt(d.UpdatedAt, "-"))
		}
	case "domain enable", "domain disable", "domain delete":
		if len(rest) != 1 {
			return fmt.Errorf("usage: domain %s <fqdn>", sub)
		}
		if sub == "delete" {
			err = db.deleteDomain(rest[0])
		} else {
			err = db.setDomainEnabled(rest[0], sub == "enable")
		}
		if err != nil {
			return err
		}
		fmt.Printf("domain %s: %sd\n", rest[0], sub)

	default:
		return fmt.Errorf("unknown command %q (run without args for help)", cmd+" "+sub)
	}
	return nil
}

// splitPositional lets flags come before or after the positional argument.
func splitPositional(args []string) (string, []string) {
	pos, rest := splitPositionals(args, 1)
	if len(pos) == 0 {
		return "", rest
	}
	return pos[0], rest
}

func splitPositionals(args []string, n int) (pos, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			if !containsEq(a) && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		if len(pos) < n {
			pos = append(pos, a)
		} else {
			flags = append(flags, a)
		}
	}
	return
}

func containsEq(s string) bool {
	for _, c := range s {
		if c == '=' {
			return true
		}
	}
	return false
}

func joinArgs(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}

func ns(v sql.NullString) string {
	if !v.Valid {
		return "-"
	}
	return v.String
}

func nt(t sql.NullTime, empty string) string {
	if !t.Valid {
		return empty
	}
	return t.Time.Format(time.DateTime)
}
