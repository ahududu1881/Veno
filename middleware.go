// middleware.go — Veno V3.0 | HTTP Middleware Chain
// Order: accessLog → recover → requestID → security → gzip → WAF → rateLimit → handler
package main

import (
	"compress/gzip"; "fmt"; "math"; "net"; "net/http"; "strings"; "sync"; "time"
	"github.com/google/uuid"
)

func buildChain(cfg *ServerConfig, waf *WAFEngine) http.Handler {
	var h http.Handler = serverHandler(cfg)
	h = rateLimitMW(cfg,h); h = wafMW(waf,cfg,h)
	if cfg.EnableGzip { h = gzipMW(h) }
	h = securityMW(cfg,h); h = recoverMW(cfg,h); h = requestIDMW(h); h = logMW(h)
	return h
}

type statusWriter struct{ http.ResponseWriter; status int; written int64 }
func (s *statusWriter) WriteHeader(c int) { s.status=c; s.ResponseWriter.WriteHeader(c) }
func (s *statusWriter) Write(b []byte) (int,error) {
	n,err:=s.ResponseWriter.Write(b); s.written+=int64(n); return n,err }

func logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start:=time.Now(); sw:=&statusWriter{ResponseWriter:w,status:200}
		next.ServeHTTP(sw,r)
		ip,_,_:=net.SplitHostPort(r.RemoteAddr)
		Log.Req(INFO,"http",r.Method+" "+r.URL.Path,r.Header.Get("X-Request-ID"),
			map[string]interface{}{"ip":ip,"status":sw.status,"bytes":sw.written,
				"ms":float64(time.Since(start).Microseconds())/1000,"ua":r.UserAgent(),"host":r.Host})
	})
}

func recoverMW(cfg *ServerConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v:=recover(); v!=nil {
				Log.Req(ERROR,"recover","Panic",r.Header.Get("X-Request-ID"),
					map[string]interface{}{"panic":fmt.Sprintf("%v",v),"path":r.URL.Path})
				serveError(w,cfg,http.StatusInternalServerError) }
		}()
		next.ServeHTTP(w,r)
	})
}

func requestIDMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id:=r.Header.Get("X-Request-ID")
		if id=="" { id=uuid.New().String(); r.Header.Set("X-Request-ID",id) }
		w.Header().Set("X-Request-ID",id); next.ServeHTTP(w,r)
	})
}

func securityMW(cfg *ServerConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h:=w.Header(); for k,v:=range cfg.Headers{h.Set(k,v)}; h.Set("Server","Veno/3.0")
		cors:=cfg.CORS
		if len(cors.Origins)>0 {
			origin:=r.Header.Get("Origin"); allowed:=false
			for _,o:=range cors.Origins{if o=="*"||o==origin{allowed=true;break}}
			if allowed {
				if len(cors.Origins)==1&&cors.Origins[0]=="*" { h.Set("Access-Control-Allow-Origin","*") } else {
					h.Set("Access-Control-Allow-Origin",origin); h.Add("Vary","Origin") }
				if len(cors.Methods)>0{h.Set("Access-Control-Allow-Methods",strings.Join(cors.Methods,", "))}
				if len(cors.ReqHeaders)>0{h.Set("Access-Control-Allow-Headers",strings.Join(cors.ReqHeaders,", "))}
				if len(cors.ExpHeaders)>0{h.Set("Access-Control-Expose-Headers",strings.Join(cors.ExpHeaders,", "))}
				if cors.Creds{h.Set("Access-Control-Allow-Credentials","true")}
				h.Set("Access-Control-Max-Age",fmt.Sprintf("%d",cors.MaxAge)) }
			if r.Method==http.MethodOptions{w.WriteHeader(http.StatusNoContent);return} }
		next.ServeHTTP(w,r)
	})
}

type gzipRW struct{ http.ResponseWriter; gz *gzip.Writer }
func (g *gzipRW) Write(b []byte) (int,error) { return g.gz.Write(b) }
func (g *gzipRW) WriteHeader(code int) { g.ResponseWriter.Header().Del("Content-Length"); g.ResponseWriter.WriteHeader(code) }

func gzipMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"),"gzip"){next.ServeHTTP(w,r);return}
		for _,skip:=range []string{"image/","video/","audio/","application/zip","application/gzip"} {
			if strings.HasPrefix(r.Header.Get("Content-Type"),skip){next.ServeHTTP(w,r);return} }
		gz,err:=gzip.NewWriterLevel(w,gzip.BestSpeed); if err!=nil{next.ServeHTTP(w,r);return}
		defer gz.Close(); w.Header().Set("Content-Encoding","gzip"); w.Header().Add("Vary","Accept-Encoding")
		next.ServeHTTP(&gzipRW{ResponseWriter:w,gz:gz},r)
	})
}

func wafMW(engine *WAFEngine, cfg *ServerConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if engine==nil||!engine.cfg.Enabled{next.ServeHTTP(w,r);return}
		if clean,_,_:=engine.Inspect(r); !clean{serveError(w,cfg,http.StatusForbidden);return}
		next.ServeHTTP(w,r)
	})
}

type bucket struct{ tokens float64; last time.Time; strikes int; bannedUntil time.Time }
type limiterStore struct{ mu sync.Mutex; buckets map[string]*bucket }
var limiters sync.Map
func getStore(id string) *limiterStore {
	v,_:=limiters.LoadOrStore(id,&limiterStore{buckets:make(map[string]*bucket)}); return v.(*limiterStore) }

func rateLimitMW(cfg *ServerConfig, next http.Handler) http.Handler {
	rc:=cfg.Rate; if !rc.Enabled{return next}
	if rc.Burst<=0{rc.Burst=rc.Limit}; if rc.Window<=0{rc.Window=60}; if rc.Cost<=0{rc.Cost=1}
	store:=getStore(cfg.ID)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip,_,_:=net.SplitHostPort(r.RemoteAddr); key:=ip
		if rc.Key=="header" { if fwd:=r.Header.Get("X-Forwarded-For");fwd!=""{key=strings.SplitN(fwd,",",2)[0]} }
		store.mu.Lock(); now:=time.Now()
		b,ok:=store.buckets[key]; if !ok{b=&bucket{tokens:float64(rc.Burst),last:now};store.buckets[key]=b}
		if !b.bannedUntil.IsZero()&&now.Before(b.bannedUntil) {
			store.mu.Unlock()
			w.Header().Set("Retry-After",fmt.Sprintf("%d",int(b.bannedUntil.Sub(now).Seconds())))
			serveError(w,cfg,http.StatusTooManyRequests); return }
		rate:=float64(rc.Limit)/float64(rc.Window)
		b.tokens=math.Min(float64(rc.Burst),b.tokens+rate*now.Sub(b.last).Seconds()); b.last=now
		if b.tokens<float64(rc.Cost) {
			b.strikes++
			if rc.BanAt>0&&b.strikes>=rc.BanAt {
				dur:=rc.BanSec; if dur<=0{dur=60}
				b.bannedUntil=now.Add(time.Duration(dur)*time.Second); b.strikes=0
				Log.Req(WARN,"ratelimit","IP banned",r.Header.Get("X-Request-ID"),map[string]interface{}{"ip":key,"ban_sec":dur}) }
			store.mu.Unlock()
			w.Header().Set("Retry-After",fmt.Sprintf("%d",int(float64(rc.Cost-1)/rate)))
			serveError(w,cfg,http.StatusTooManyRequests); return }
		b.tokens-=float64(rc.Cost); b.strikes=0; store.mu.Unlock()
		next.ServeHTTP(w,r)
	})
}
