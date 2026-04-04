// cache.go — Veno V3.0 | LRU Cache + Memory Warden
package main

import (
	"bytes"; "net/http"; "runtime"; "sync"; "sync/atomic"; "time"
)

type CacheItem struct{ Body []byte; Headers http.Header; StatusCode int; ExpiresAt time.Time; Size int64 }
type cacheNode struct{ key string; item CacheItem; prev, next *cacheNode }
type LRUCache struct {
	mu sync.Mutex; cap int; maxBytes, used int64; nodes map[string]*cacheNode
	head, tail *cacheNode; hits, misses, evictions uint64
}

var GlobalCache *LRUCache

func initCache(maxEntries, maxMB int) {
	if maxEntries<=0{maxEntries=CacheCfg.MaxEntries}; if maxMB<=0{maxMB=CacheCfg.MaxMemMB}
	if maxEntries<=0{maxEntries=20000}; if maxMB<=0{maxMB=128}
	c := &LRUCache{cap:maxEntries,maxBytes:int64(maxMB)*1024*1024,nodes:make(map[string]*cacheNode)}
	c.head=&cacheNode{}; c.tail=&cacheNode{}; c.head.next=c.tail; c.tail.prev=c.head
	GlobalCache=c; go c.sweepLoop()
}
func (c *LRUCache) sweepLoop() {
	t:=time.NewTicker(30*time.Second); defer t.Stop()
	for range t.C { c.mu.Lock(); now:=time.Now()
		for k,n:=range c.nodes { if now.After(n.item.ExpiresAt) {
			c.used-=n.item.Size; c.remove(n); delete(c.nodes,k); atomic.AddUint64(&c.evictions,1) } }
		c.mu.Unlock() }
}
func (c *LRUCache) Get(key string) (CacheItem, bool) {
	c.mu.Lock(); defer c.mu.Unlock()
	n,ok:=c.nodes[key]; if !ok{atomic.AddUint64(&c.misses,1);return CacheItem{},false}
	if time.Now().After(n.item.ExpiresAt) {
		c.used-=n.item.Size; c.remove(n); delete(c.nodes,key)
		atomic.AddUint64(&c.misses,1); atomic.AddUint64(&c.evictions,1); return CacheItem{},false }
	c.detach(n); c.pushFront(n); atomic.AddUint64(&c.hits,1); return n.item,true
}
func (c *LRUCache) Set(key string, item CacheItem) {
	c.mu.Lock(); defer c.mu.Unlock()
	if n,ok:=c.nodes[key]; ok {
		c.used+=item.Size-n.item.Size; n.item=item; c.detach(n); c.pushFront(n); return }
	for (len(c.nodes)>=c.cap||c.used+item.Size>c.maxBytes) && c.tail.prev!=c.head {
		lru:=c.tail.prev; c.used-=lru.item.Size; c.remove(lru); delete(c.nodes,lru.key); atomic.AddUint64(&c.evictions,1) }
	n:=&cacheNode{key:key,item:item}; c.nodes[key]=n; c.pushFront(n); c.used+=item.Size
}
func (c *LRUCache) Evict(pct int) {
	c.mu.Lock(); defer c.mu.Unlock(); target:=len(c.nodes)*pct/100
	for i:=0; i<target&&c.tail.prev!=c.head; i++ {
		lru:=c.tail.prev; c.used-=lru.item.Size; c.remove(lru); delete(c.nodes,lru.key); atomic.AddUint64(&c.evictions,1) }
}
func (c *LRUCache) Stats() map[string]interface{} {
	c.mu.Lock(); n:=len(c.nodes); used:=c.used; c.mu.Unlock()
	total:=atomic.LoadUint64(&c.hits)+atomic.LoadUint64(&c.misses); ratio:=float64(0)
	if total>0{ratio=float64(atomic.LoadUint64(&c.hits))/float64(total)}
	return map[string]interface{}{"entries":n,"hits":atomic.LoadUint64(&c.hits),
		"misses":atomic.LoadUint64(&c.misses),"evictions":atomic.LoadUint64(&c.evictions),
		"hit_ratio":ratio,"used_bytes":used}
}
func (c *LRUCache) pushFront(n *cacheNode) {
	n.prev=c.head; n.next=c.head.next; c.head.next.prev=n; c.head.next=n }
func (c *LRUCache) detach(n *cacheNode) { n.prev.next=n.next; n.next.prev=n.prev }
func (c *LRUCache) remove(n *cacheNode) { n.prev.next=n.next; n.next.prev=n.prev }

type cacheCapture struct{ http.ResponseWriter; body *bytes.Buffer; status int }
func newCapture(w http.ResponseWriter) *cacheCapture {
	return &cacheCapture{ResponseWriter:w,body:bytes.NewBuffer(make([]byte,0,4096)),status:200} }
func (c *cacheCapture) WriteHeader(s int) { c.status=s; c.ResponseWriter.WriteHeader(s) }
func (c *cacheCapture) Write(b []byte) (int,error) { c.body.Write(b); return c.ResponseWriter.Write(b) }

type MemoryWarden struct{ maxBytes uint64; cache *LRUCache; done chan struct{} }
func newMemoryWarden(maxMB int, cache *LRUCache) *MemoryWarden {
	if maxMB<=0{maxMB=MemCfg.GCThreshMB}; if maxMB<=0{maxMB=512}
	return &MemoryWarden{maxBytes:uint64(maxMB)*1024*1024,cache:cache,done:make(chan struct{})}
}
func (w *MemoryWarden) Start() {
	go func() {
		t:=time.NewTicker(60*time.Second); defer t.Stop()
		for { select {
			case <-t.C:
				var ms runtime.MemStats; runtime.ReadMemStats(&ms)
				if w.maxBytes>0&&ms.Alloc>w.maxBytes {
					Log.Warn("memory","Heap pressure — evicting+GC",map[string]interface{}{
						"alloc_mb":ms.Alloc/1024/1024,"threshold_mb":w.maxBytes/1024/1024})
					w.cache.Evict(30); runtime.GC() }
				runtime.GC()
			case <-w.done: return } }
	}()
}
func (w *MemoryWarden) Stop() { close(w.done) }
