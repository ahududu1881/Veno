// config.go — Veno V3.0 | Configuration Engine
//
// Load order: .veno/root.lock → config/env.toml → config/app.toml
//             → config/security.toml → config/routes.toml
//
// Security profiles resolved to concrete values — nothing hardcoded in Go.
// All "var.KEY" refs resolved from config/env.toml.
// Every file op uses SafePath(CorePath,…) — traversal impossible.
package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// ── Runtime structs ────────────────────────────────────────────────────────

type ServerConfig struct {
	ID, Port, Domain, Folder, ErrorFolder, Privacy string
	EnableGzip bool
	TLS        TLSRuntime
	CORS       CORSRuntime
	Headers    map[string]string
	Redirects  []RedirectRule
	WAF        WAFRuntime
	Rate       RateRuntime
	Upstream   *UpstreamPool
	Locations  map[string]*LocationConfig
}

type TLSRuntime  struct{ Enabled bool; Cert, Key, MinVer string }
type CORSRuntime struct {
	Origins, Methods, ReqHeaders, ExpHeaders []string
	Creds bool; MaxAge int
}
type RedirectRule   struct{ From, To string; Code int; Re *regexp.Regexp }
type WAFRuntime     struct{ Enabled bool; Score int; MaxBody int64; LogOnly bool; Allow, Block []string }
type RateRuntime    struct{ Enabled bool; Limit, Burst, Window, BanAt, BanSec, Cost int; Key string }
type LocationConfig struct{ Pool *UpstreamPool; Folder string; StripPrefix bool }
type CBConfig       struct{ MaxFail, ResetSec, Probes int }

type UpstreamPool struct {
	Nodes          []*UpNode
	Strategy       string
	HealthPath     string
	HealthInterval int
	CacheEnabled   bool
	CacheTTL       int
	CB             CBConfig
	Counter        uint64
}

type UpNode struct {
	Raw string; URL *url.URL; Alive int32; Weight int; Circuit *CircuitBreaker
}

// ── TOML parse structs ─────────────────────────────────────────────────────

type appTOML struct {
	Server struct {
		Name, Version, Environment, LogLevel string
		Listener []struct {
			ID, Domain, DomainVar, Folder, ErrorFolder, Privacy string
			Port int; Gzip bool
		} `toml:"listener"`
		TLS struct {
			Enabled bool; CertFile, KeyFile, MinVer string
		} `toml:"tls"`
		Timeouts struct{ Read, Write, Idle, Drain int } `toml:"timeouts"`
	} `toml:"server"`
	Cache  struct{ Enabled bool; MaxEntries, MaxMemMB int } `toml:"cache"`
	Memory struct{ GCThreshMB int `toml:"gc_threshold_mb"` } `toml:"memory"`
}

type secTOML struct {
	WAF struct {
		Enabled bool; Profile string
		Custom struct {
			Score     int      `toml:"block_score"`
			MaxBodyMB int64    `toml:"max_body_mb"`
			LogOnly   bool     `toml:"log_only"`
			Allow     []string `toml:"ip_whitelist"`
			Block     []string `toml:"ip_blacklist"`
		} `toml:"custom"`
	} `toml:"waf"`
	Rate struct {
		Enabled bool; Profile, Key string
		Custom struct {
			Requests, Burst, Window, BanAt, BanSecs int
		} `toml:"custom"`
	} `toml:"rate_limit"`
	CORS struct {
		Enabled  bool
		Origins, Methods, Headers, ExposeH []string
		Creds    bool; MaxAge int
	} `toml:"cors"`
	Headers  map[string]string `toml:"headers"`
	Redirect []struct{ From, To string; Status int } `toml:"redirect"`
}

type routesTOML struct {
	Upstream []struct {
		ID, Location, Strategy, HealthCheck string
		StripPrefix    bool
		Nodes          []string; Weights []int
		HealthInterval, CacheTTL int; CacheEnabled bool
		CB struct{ MaxFail, ResetSec, Probes int `toml:"max_failures,reset_timeout,probes"` } `toml:"circuit_breaker"`
	} `toml:"upstream"`
}

type envTOML struct{ Vars map[string]string `toml:"vars"` }

// ── Global state ───────────────────────────────────────────────────────────

var (
	CorePath string
	Configs  []*ServerConfig
	AppMeta  struct{ Name, Version, Env, LogLevel string }
	Timeouts struct{ Read, Write, Idle, Drain int }
	CacheCfg struct{ Enabled bool; MaxEntries, MaxMemMB int }
	MemCfg   struct{ GCThreshMB int }
	envVars  map[string]string
	cfgLock  sync.RWMutex
)

// ── Security profile tables ────────────────────────────────────────────────

var wafProfiles = map[string]struct{ Score int; MaxBodyMB int64; LogOnly bool }{
	"strict": {6, 5, false}, "normal": {10, 10, false},
	"relaxed": {15, 50, true}, "dev": {25, 100, true},
}
var rateProfiles = map[string][5]int{
	"strict": {100, 150, 60, 10, 3600}, "normal": {500, 1000, 60, 50, 300},
	"relaxed": {2000, 5000, 60, 200, 60}, "dev": {10000, 20000, 60, 0, 0},
}

// ── Init ───────────────────────────────────────────────────────────────────

func initConfig() {
	CorePath = findCoreRoot()
	envVars = make(map[string]string)
	loadEnv(); loadApp(); loadSecurityAndRoutes()
}

func findCoreRoot() string {
	exe, err := os.Executable()
	if err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
		dir := filepath.Dir(exe)
		for i := 0; i < 6; i++ {
			if _, e := os.Stat(filepath.Join(dir, ".veno", "root.lock")); e == nil {
				if root, err := readRootLock(dir); err == nil { return root }
			}
			parent := filepath.Dir(dir)
			if parent == dir { break }
			dir = parent
		}
	}
	cwd, _ := os.Getwd()
	if _, e := os.Stat(filepath.Join(cwd, ".veno", "root.lock")); e == nil {
		if root, err := readRootLock(cwd); err == nil { return root }
	}
	fmt.Fprintf(os.Stderr, "[WARN] .veno/root.lock not found, using cwd\n")
	return cwd
}

func readRootLock(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, ".veno", "root.lock"))
	if err != nil { return "", err }
	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 3)
	if len(lines) == 0 { return "", fmt.Errorf("empty lock") }
	root := strings.TrimSpace(lines[0])
	if _, err := os.Stat(root); err != nil { return "", fmt.Errorf("lock path invalid: %w", err) }
	return root, nil
}

func cfgPath(name string) string {
	p, err := SafePath(CorePath, filepath.Join("config", name))
	if err != nil { Log.Fatal("config", "Config path traversal: "+name, nil) }
	return p
}

func resolveVar(s string) string {
	if strings.HasPrefix(s, "var.") {
		key := strings.TrimPrefix(s, "var.")
		if v, ok := envVars[key]; ok { return v }
		if Log != nil { Log.Warn("config", "Unresolved var ref", map[string]interface{}{"ref": s}) }
	}
	return s
}

func loadEnv() {
	p := cfgPath("env.toml")
	if _, err := os.Stat(p); os.IsNotExist(err) { return }
	var raw envTOML
	if _, err := toml.DecodeFile(p, &raw); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] env.toml: %v\n", err); return
	}
	for k, v := range raw.Vars { envVars[k] = v }
}

func loadApp() {
	p := cfgPath("app.toml")
	var raw appTOML
	if _, err := toml.DecodeFile(p, &raw); err != nil {
		fmt.Fprintf(os.Stderr, "[FATAL] app.toml: %v\n", err); os.Exit(1)
	}
	s := raw.Server
	AppMeta.Name = s.Name; AppMeta.Version = s.Version
	AppMeta.Env = s.Environment; AppMeta.LogLevel = s.LogLevel
	if AppMeta.Env == "" { AppMeta.Env = "production" }
	if AppMeta.LogLevel == "" { AppMeta.LogLevel = "info" }
	Timeouts.Read = s.Timeouts.Read; Timeouts.Write = s.Timeouts.Write
	Timeouts.Idle = s.Timeouts.Idle; Timeouts.Drain = s.Timeouts.Drain
	if Timeouts.Read <= 0 { Timeouts.Read = 30 }; if Timeouts.Write <= 0 { Timeouts.Write = 30 }
	if Timeouts.Idle <= 0 { Timeouts.Idle = 120 }; if Timeouts.Drain <= 0 { Timeouts.Drain = 15 }
	CacheCfg.Enabled = raw.Cache.Enabled
	CacheCfg.MaxEntries = raw.Cache.MaxEntries; CacheCfg.MaxMemMB = raw.Cache.MaxMemMB
	if CacheCfg.MaxEntries <= 0 { CacheCfg.MaxEntries = 20000 }
	if CacheCfg.MaxMemMB <= 0   { CacheCfg.MaxMemMB = 128 }
	MemCfg.GCThreshMB = raw.Memory.GCThreshMB
	if MemCfg.GCThreshMB <= 0   { MemCfg.GCThreshMB = 512 }
}

func loadSecurityAndRoutes() {
	p := cfgPath("security.toml")
	var sec secTOML
	if _, err := toml.DecodeFile(p, &sec); err != nil {
		Log.Fatal("config", "security.toml failed", map[string]interface{}{"err": err.Error()})
	}
	wafR  := resolveWAF(sec)
	rateR := resolveRate(sec)
	cors  := buildCORS(sec)
	hdrs  := buildHeaders(sec.Headers)
	redirs := buildRedirects(sec)

	var routes routesTOML
	rp := cfgPath("routes.toml")
	if _, err := os.Stat(rp); err == nil {
		if _, err2 := toml.DecodeFile(rp, &routes); err2 != nil {
			Log.Warn("config", "routes.toml parse error", map[string]interface{}{"err": err2.Error()})
		}
	}
	upstreams := buildUpstreams(routes)

	var rawApp appTOML
	toml.DecodeFile(cfgPath("app.toml"), &rawApp)
	tls := rawApp.Server.TLS

	cfgLock.Lock(); defer cfgLock.Unlock()
	for _, l := range rawApp.Server.Listener {
		domain := l.Domain
		if l.DomainVar != "" { domain = resolveVar("var." + l.DomainVar) }
		if domain == "" { domain = "localhost" }
		folder := l.Folder; if folder == "" { folder = "public" }
		errF := l.ErrorFolder; if errF == "" { errF = "errors" }
		priv := l.Privacy; if priv == "" { priv = "any" }
		cfg := &ServerConfig{
			ID: l.ID, Port: strconv.Itoa(l.Port), Domain: domain,
			Folder: folder, ErrorFolder: errF, Privacy: priv, EnableGzip: l.Gzip,
			TLS: TLSRuntime{Enabled: tls.Enabled, Cert: tls.CertFile, Key: tls.KeyFile, MinVer: tls.MinVer},
			CORS: cors, Headers: hdrs, Redirects: redirs, WAF: wafR, Rate: rateR,
			Locations: make(map[string]*LocationConfig),
		}
		for loc, pool := range upstreams {
			if loc == "__default__" { cfg.Upstream = pool } else {
				cfg.Locations[loc] = &LocationConfig{Pool: pool}
			}
		}
		Configs = append(Configs, cfg)
	}
	if len(Configs) == 0 {
		Log.Fatal("config", "app.toml has no [[server.listener]] entries", nil)
	}
}

func resolveWAF(sec secTOML) WAFRuntime {
	w := sec.WAF
	p, ok := wafProfiles[w.Profile]
	if !ok || w.Profile == "custom" {
		p.Score = w.Custom.Score; p.MaxBodyMB = w.Custom.MaxBodyMB; p.LogOnly = w.Custom.LogOnly
		if p.Score <= 0 { p.Score = 10 }; if p.MaxBodyMB <= 0 { p.MaxBodyMB = 10 }
	}
	return WAFRuntime{Enabled: w.Enabled, Score: p.Score, MaxBody: p.MaxBodyMB * 1024 * 1024,
		LogOnly: p.LogOnly, Allow: w.Custom.Allow, Block: w.Custom.Block}
}

func resolveRate(sec secTOML) RateRuntime {
	r := sec.Rate
	rr := RateRuntime{Enabled: r.Enabled, Key: r.Key, Cost: 1}
	if rr.Key == "" { rr.Key = "ip" }
	if p, ok := rateProfiles[r.Profile]; ok && r.Profile != "custom" {
		rr.Limit = p[0]; rr.Burst = p[1]; rr.Window = p[2]; rr.BanAt = p[3]; rr.BanSec = p[4]
	} else {
		rr.Limit = r.Custom.Requests; rr.Burst = r.Custom.Burst
		rr.Window = r.Custom.Window; rr.BanAt = r.Custom.BanAt; rr.BanSec = r.Custom.BanSecs
		if rr.Limit <= 0 { rr.Limit = 500 }; if rr.Burst <= 0 { rr.Burst = 1000 }
		if rr.Window <= 0 { rr.Window = 60 }
	}
	return rr
}

func buildCORS(sec secTOML) CORSRuntime {
	c := sec.CORS
	if len(c.Origins) == 0 { c.Origins = []string{"*"} }
	if len(c.Methods) == 0 { c.Methods = []string{"GET","POST","PUT","DELETE","PATCH","OPTIONS"} }
	if len(c.Headers) == 0 { c.Headers = []string{"Authorization","Content-Type","X-Request-ID"} }
	if c.MaxAge <= 0         { c.MaxAge = 3600 }
	return CORSRuntime{Origins: c.Origins, Methods: c.Methods,
		ReqHeaders: c.Headers, ExpHeaders: c.ExposeH, Creds: c.Creds, MaxAge: c.MaxAge}
}

func buildHeaders(h map[string]string) map[string]string {
	out := map[string]string{
		"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
		"X-XSS-Protection": "1; mode=block", "Referrer-Policy": "strict-origin-when-cross-origin",
		"Permissions-Policy": "geolocation=(), microphone=(), camera=()",
	}
	for k, v := range h { out[k] = v }
	return out
}

func buildRedirects(sec secTOML) []RedirectRule {
	var out []RedirectRule
	for _, r := range sec.Redirect {
		re, err := regexp.Compile(r.From)
		if err != nil { Log.Warn("config", "Bad redirect regex", map[string]interface{}{"from": r.From}); continue }
		code := r.Status; if code == 0 { code = 301 }
		out = append(out, RedirectRule{From: r.From, To: r.To, Code: code, Re: re})
	}
	return out
}

func buildUpstreams(routes routesTOML) map[string]*UpstreamPool {
	out := make(map[string]*UpstreamPool)
	for _, u := range routes.Upstream {
		if len(u.Nodes) == 0 { continue }
		cb := CBConfig{MaxFail: u.CB.MaxFail, ResetSec: u.CB.ResetSec, Probes: u.CB.Probes}
		if cb.MaxFail <= 0 { cb.MaxFail = 5 }; if cb.ResetSec <= 0 { cb.ResetSec = 30 }
		if cb.Probes <= 0 { cb.Probes = 1 }
		strat := u.Strategy; if strat == "" { strat = "round_robin" }
		pool := &UpstreamPool{Strategy: strat, HealthPath: u.HealthCheck,
			HealthInterval: u.HealthInterval, CacheEnabled: u.CacheEnabled, CacheTTL: u.CacheTTL, CB: cb}
		if pool.HealthInterval <= 0 { pool.HealthInterval = 15 }
		for i, node := range u.Nodes {
			resolved := resolveVar(node)
			parsed, err := url.Parse(resolved)
			if err != nil || parsed.Host == "" {
				Log.Warn("config", "Invalid upstream URL", map[string]interface{}{"url": resolved}); continue
			}
			w := 1; if i < len(u.Weights) { w = u.Weights[i] }
			pool.Nodes = append(pool.Nodes, &UpNode{Raw: resolved, URL: parsed, Alive: 1,
				Weight: w, Circuit: NewCircuitBreaker(cb)})
		}
		loc := u.Location; if loc == "" || loc == "/" { loc = "__default__" }
		out[loc] = pool
	}
	return out
}
