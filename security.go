// security.go — Veno V3.0 | WAF Engine + Circuit Breaker
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type wafRule struct{ ID, Name string; Re *regexp.Regexp; Score int; Targets []string }
type WAFEngine struct{ cfg WAFRuntime; rules []*wafRule; allow, block sync.Map }

var builtinRules = []struct{ id, name, pattern string; score int; targets []string }{
	{"SQLI-01","UNION SELECT",      `(?i)\bunion\b[\s\S]{0,100}\bselect\b`,                10,[]string{"all"}},
	{"SQLI-02","Tautology",         `(?i)(\bor\b|\band\b)\s+[\w'"]+\s*=\s*[\w'"]+`,        9, []string{"all"}},
	{"SQLI-03","Stacked Queries",   `(?i);\s*(drop|insert|update|delete|create|truncate)\b`,10,[]string{"all"}},
	{"SQLI-04","Blind/Time-based",  `(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)`,      9, []string{"all"}},
	{"SQLI-05","Schema Disclosure", `(?i)(information_schema|pg_tables|sqlite_master)`,      8, []string{"all"}},
	{"XSS-01", "Script Tag",        `(?i)<\s*script[\s>]`,                                  10,[]string{"all"}},
	{"XSS-02", "Event Handler",     `(?i)\bon\w{1,20}\s*=`,                                  8, []string{"query","body","headers"}},
	{"XSS-03", "JavaScript URI",    `(?i)javascript\s*:`,                                    9, []string{"all"}},
	{"XSS-04", "Dangerous Tags",    `(?i)<\s*(svg|object|embed|iframe|applet)[\s/>]`,        7, []string{"all"}},
	{"XSS-05", "Data URI",          `(?i)data\s*:\s*[^,]*base64`,                            6, []string{"all"}},
	{"PT-01",  "Dir Traversal",     `(?:\.\.\/|\.\.\\)`,                                     10,[]string{"path","query"}},
	{"PT-02",  "Encoded Traversal", `(?i)(%2e%2e[%2f%5c]|\.\.%2f|%2e\.%2f)`,                10,[]string{"path","query"}},
	{"PT-03",  "Double Encoded",    `(?i)%252e%252e`,                                         10,[]string{"path","query"}},
	{"PT-04",  "Null Byte",         `(?:%00|\x00)`,                                           8, []string{"all"}},
	{"RFI-01", "Remote Include",    `(?i)(https?|ftp)://[^/]+/[^?#]*\.(php|asp|jsp|cgi)`,   9, []string{"query","body"}},
	{"CMD-01", "Shell Chain",       `[;&|]\s*(ls|cat|echo|id|whoami|wget|curl|bash|sh|python|perl|nc)\b`,10,[]string{"all"}},
	{"CMD-02", "Backtick",          "`[^`]{1,200}`",                                          9, []string{"all"}},
	{"CMD-03", "Dollar Sub",        `\$\([^)]{1,200}\)`,                                      8, []string{"all"}},
	{"CMD-04", "Sensitive Paths",   `(?i)(/etc/passwd|/etc/shadow|/proc/self|/bin/(sh|bash))`,9,[]string{"all"}},
	{"SCAN-01","Scanner UA",        `(?i)(nikto|nmap|sqlmap|acunetix|burpsuite|dirbuster|gobuster|nuclei|wfuzz)`,8,[]string{"headers"}},
	{"SCAN-02","Probe Paths",       `(?i)/(\.env|\.git|\.svn|phpinfo\.php|wp-config\.php|admin/config)`,6,[]string{"path"}},
	{"PROTO-01","Smuggling",        `(?i)(transfer-encoding\s*:\s*chunked[\s\S]{0,20}content-length)`,10,[]string{"headers"}},
	{"PROTO-02","CRLF Injection",   `(?:\r\n|\n)(?:HTTP/|\w+:)`,                             8, []string{"all"}},
}

func NewWAFEngine(cfg WAFRuntime) *WAFEngine {
	if cfg.Score <= 0 { cfg.Score = 10 }; if cfg.MaxBody <= 0 { cfg.MaxBody = 10*1024*1024 }
	e := &WAFEngine{cfg: cfg}
	for _, r := range builtinRules {
		rx, err := regexp.Compile(r.pattern)
		if err != nil { if Log != nil { Log.Warn("waf", fmt.Sprintf("rule %s compile error", r.id), nil) }; continue }
		e.rules = append(e.rules, &wafRule{ID: r.id, Name: r.name, Re: rx, Score: r.score, Targets: r.targets})
	}
	for _, ip := range cfg.Allow { e.allow.Store(ip, struct{}{}) }
	for _, ip := range cfg.Block { e.block.Store(ip, struct{}{}) }
	return e
}

func (e *WAFEngine) Inspect(r *http.Request) (bool, int, string) {
	if !e.cfg.Enabled { return true, 0, "" }
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if _, ok := e.allow.Load(clientIP); ok { return true, 0, "" }
	if _, ok := e.block.Load(clientIP); ok {
		Log.Req(WARN, "waf", "Blacklisted IP", r.Header.Get("X-Request-ID"), map[string]interface{}{"ip": clientIP})
		if e.cfg.LogOnly { return true, 0, "BLACKLIST" }
		return false, 10, "BLACKLIST"
	}
	path := r.URL.Path; query := r.URL.RawQuery; ua := r.UserAgent()
	headers := r.Header.Get("Content-Type")+" "+r.Header.Get("Referer")+" "+ua
	var body string
	if r.Body != nil && r.ContentLength != 0 {
		if b, err := io.ReadAll(io.LimitReader(r.Body, e.cfg.MaxBody)); err == nil {
			body = string(b); r.Body = io.NopCloser(strings.NewReader(body))
		}
	}
	score := 0; matched := ""
	if ua == "" {
		score += 3; matched = "SCAN-UA"
		Log.Req(WARN, "waf", "Empty User-Agent", r.Header.Get("X-Request-ID"),
			map[string]interface{}{"ip": clientIP, "score": 3})
	}
	for _, rule := range e.rules {
		for _, t := range rule.Targets {
			var hay string
			switch t {
			case "path": hay=path; case "query": hay=query; case "body": hay=body
			case "headers": hay=headers; case "all": hay=path+" "+query+" "+body+" "+headers
			}
			if hay == "" { continue }
			if rule.Re.MatchString(hay) {
				score += rule.Score; if matched == "" { matched = rule.ID }
				Log.Req(WARN, "waf", fmt.Sprintf("Rule %s: %s", rule.ID, rule.Name),
					r.Header.Get("X-Request-ID"),
					map[string]interface{}{"ip":clientIP,"rule":rule.ID,"score":rule.Score,"total":score,"path":path})
				break
			}
		}
		if score >= e.cfg.Score { break }
	}
	if score >= e.cfg.Score {
		if e.cfg.LogOnly {
			Log.Req(WARN,"waf","WAF would block (log_only)",r.Header.Get("X-Request-ID"),
				map[string]interface{}{"ip":clientIP,"score":score,"rule":matched})
			return true, score, matched
		}
		return false, score, matched
	}
	return true, score, ""
}

// ── Circuit Breaker ───────────────────────────────────────────────────────

type CBState int
const (StateClosed CBState = iota; StateOpen; StateHalfOpen)
func (s CBState) String() string { return [...]string{"CLOSED","OPEN","HALF_OPEN"}[s] }

type CircuitBreaker struct {
	mu sync.Mutex; state CBState; failures, halfSucc int
	lastFailure time.Time; cfg CBConfig
}

func NewCircuitBreaker(cfg CBConfig) *CircuitBreaker {
	if cfg.MaxFail<=0{cfg.MaxFail=5};if cfg.ResetSec<=0{cfg.ResetSec=30};if cfg.Probes<=0{cfg.Probes=1}
	return &CircuitBreaker{state: StateClosed, cfg: cfg}
}
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock(); defer cb.mu.Unlock()
	switch cb.state {
	case StateClosed: return true
	case StateOpen:
		if time.Since(cb.lastFailure) >= time.Duration(cb.cfg.ResetSec)*time.Second {
			cb.state=StateHalfOpen; cb.halfSucc=0; Log.Info("circuit","→ HALF_OPEN",nil); return true
		}
		return false
	case StateHalfOpen: return true
	}
	return false
}
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock(); defer cb.mu.Unlock()
	switch cb.state {
	case StateHalfOpen:
		cb.halfSucc++
		if cb.halfSucc >= cb.cfg.Probes { cb.state=StateClosed; cb.failures=0; Log.Info("circuit","→ CLOSED",nil) }
	case StateClosed:
		if cb.failures > 0 { cb.failures-- }
	}
}
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock(); defer cb.mu.Unlock()
	cb.lastFailure = time.Now()
	switch cb.state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.cfg.MaxFail {
			cb.state = StateOpen
			Log.Warn("circuit","→ OPEN",map[string]interface{}{"failures":cb.failures,"max":cb.cfg.MaxFail})
		}
	case StateHalfOpen:
		cb.state = StateOpen; Log.Warn("circuit","→ OPEN: half-open probe failed",nil)
	}
}
func (cb *CircuitBreaker) State() CBState { cb.mu.Lock(); defer cb.mu.Unlock(); return cb.state }
