// proxy.go — Veno V3.0 | Reverse Proxy + Load Balancer + Health Checks
package main

import (
	"fmt"; "math"; "net"; "net/http"; "net/http/httputil"
	"sync"; "sync/atomic"; "time"
)

var sharedTransport = &http.Transport{
	DialContext: (&net.Dialer{Timeout:10*time.Second,KeepAlive:60*time.Second}).DialContext,
	MaxIdleConns:512,MaxIdleConnsPerHost:64,MaxConnsPerHost:256,
	IdleConnTimeout:90*time.Second,TLSHandshakeTimeout:10*time.Second,ExpectContinueTimeout:1*time.Second,
}
var healthClient = &http.Client{Timeout:3*time.Second,Transport:&http.Transport{
	MaxIdleConns:32,MaxIdleConnsPerHost:4,IdleConnTimeout:15*time.Second}}
var inflightMap sync.Map
func inflightOf(n *UpNode) *int64 { v,_:=inflightMap.LoadOrStore(n,new(int64)); return v.(*int64) }

func ProxyRequest(w http.ResponseWriter, r *http.Request, pool *UpstreamPool, cfg *ServerConfig) {
	reqID := r.Header.Get("X-Request-ID")
	cacheKey := ""
	if pool.CacheEnabled && r.Method == "GET" {
		cacheKey = r.Method+"|"+r.URL.String()
		if item,found := GlobalCache.Get(cacheKey); found {
			for k,v := range item.Headers { w.Header()[k]=v }
			w.Header().Set("X-Veno-Cache","HIT"); w.WriteHeader(item.StatusCode); w.Write(item.Body); return }
	}
	alive := aliveNodes(pool)
	if len(alive) == 0 {
		Log.Req(ERROR,"proxy","No healthy upstream nodes",reqID,map[string]interface{}{"server":cfg.ID})
		serveError(w,cfg,http.StatusBadGateway); return }
	maxAttempts := int(math.Min(float64(len(alive)),3)); var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		node := pickNode(pool,alive); if node==nil { break }
		if !node.Circuit.Allow() {
			Log.Req(WARN,"proxy","Circuit OPEN",reqID,map[string]interface{}{"target":node.Raw})
			alive=dropNode(alive,node); if len(alive)==0{break}; continue }
		counter := inflightOf(node); atomic.AddInt64(counter,1)
		proxy := httputil.NewSingleHostReverseProxy(node.URL)
		proxy.Transport = sharedTransport
		proxy.ErrorHandler = func(rw http.ResponseWriter,req *http.Request,err error) {
			lastErr=err; node.Circuit.RecordFailure(); atomic.StoreInt32(&node.Alive,0)
			atomic.AddInt64(counter,-1)
			Log.Req(ERROR,"proxy","Upstream failed",req.Header.Get("X-Request-ID"),
				map[string]interface{}{"target":node.Raw,"err":err.Error(),"attempt":attempt+1}) }
		proxy.ModifyResponse = func(resp *http.Response) error {
			node.Circuit.RecordSuccess(); atomic.StoreInt32(&node.Alive,1)
			resp.Header.Set("X-Veno-Node",node.URL.Host); resp.Header.Set("X-Veno-Cache","MISS"); return nil }
		if pool.CacheEnabled && r.Method=="GET" && cacheKey!="" {
			cap := newCapture(w); proxy.ServeHTTP(cap,r); atomic.AddInt64(counter,-1)
			if lastErr!=nil{alive=dropNode(alive,node);lastErr=nil;continue}
			if cap.status>=200&&cap.status<300 {
				ttl:=pool.CacheTTL; if ttl<=0{ttl=30}; body:=cap.body.Bytes()
				GlobalCache.Set(cacheKey,CacheItem{Body:body,Headers:cap.ResponseWriter.Header().Clone(),
					StatusCode:cap.status,ExpiresAt:time.Now().Add(time.Duration(ttl)*time.Second),Size:int64(len(body))}) }
			return }
		proxy.ServeHTTP(w,r); atomic.AddInt64(counter,-1)
		if lastErr!=nil{alive=dropNode(alive,node);lastErr=nil;continue}; return
	}
	Log.Req(ERROR,"proxy","All nodes failed",reqID,map[string]interface{}{"server":cfg.ID})
	serveError(w,cfg,http.StatusBadGateway)
}

func aliveNodes(pool *UpstreamPool) []*UpNode {
	var out []*UpNode
	for _,n:=range pool.Nodes { if atomic.LoadInt32(&n.Alive)==1{out=append(out,n)} }
	return out
}
func pickNode(pool *UpstreamPool, alive []*UpNode) *UpNode {
	if len(alive)==0{return nil}
	switch pool.Strategy {
	case "least_conn":
		best:=alive[0]; min:=atomic.LoadInt64(inflightOf(best))
		for _,n:=range alive[1:] { if v:=atomic.LoadInt64(inflightOf(n));v<min{min=v;best=n} }
		return best
	case "weighted":
		total:=0; for _,n:=range alive{total+=n.Weight}
		idx:=int(atomic.AddUint64(&pool.Counter,1))%total; cum:=0
		for _,n:=range alive{cum+=n.Weight;if idx<cum{return n}}; return alive[0]
	default:
		idx:=atomic.AddUint64(&pool.Counter,1)%uint64(len(alive)); return alive[idx]
	}
}
func dropNode(nodes []*UpNode, target *UpNode) []*UpNode {
	out:=nodes[:0]; for _,n:=range nodes{if n!=target{out=append(out,n)}}; return out }

func startHealthChecks(configs []*ServerConfig) {
	for _,cfg:=range configs {
		if cfg.Upstream!=nil&&cfg.Upstream.HealthPath!="" { go healthLoop(cfg.ID,cfg.Upstream) }
		for loc,lc:=range cfg.Locations {
			if lc.Pool!=nil&&lc.Pool.HealthPath!="" { go healthLoop(cfg.ID+":"+loc,lc.Pool) } }
	}
}
func healthLoop(label string, pool *UpstreamPool) {
	interval:=time.Duration(pool.HealthInterval)*time.Second
	if interval<=0{interval=15*time.Second}
	t:=time.NewTicker(interval); defer t.Stop()
	Log.Info("health",fmt.Sprintf("Probing [%s] every %s",label,interval),nil)
	for range t.C { for _,node:=range pool.Nodes { probeNode(label,node,pool.HealthPath) } }
}
func probeNode(label string, node *UpNode, path string) {
	target:=node.URL.String(); if path!=""&&path[0]!='/'{path="/"+path}; target+=path
	resp,err:=healthClient.Get(target); wasAlive:=atomic.LoadInt32(&node.Alive)==1
	if err!=nil||resp==nil||resp.StatusCode>=400 {
		if wasAlive { atomic.StoreInt32(&node.Alive,0); node.Circuit.RecordFailure()
			Log.Warn("health","Node DOWN",map[string]interface{}{"pool":label,"node":node.Raw}) }
	} else {
		if !wasAlive { atomic.StoreInt32(&node.Alive,1); node.Circuit.RecordSuccess()
			Log.Info("health","Node UP",map[string]interface{}{"pool":label,"node":node.Raw}) }
	}
	if resp!=nil{resp.Body.Close()}
}
