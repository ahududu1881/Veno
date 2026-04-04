// server.go — Veno V3.0 | Core HTTP Handler + Built-in Endpoints
package main

import (
	"encoding/json"; "fmt"; "net"; "net/http"; "os"
	"path/filepath"; "sort"; "strings"; "time"
)

func serverHandler(cfg *ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		switch r.URL.Path {
		case "/__veno/health":
			w.Header().Set("Content-Type","application/json")
			fmt.Fprintf(w,`{"status":"ok","server":%q,"version":%q,"env":%q}`,cfg.ID,AppMeta.Version,AppMeta.Env)
			return
		case "/__veno/metrics":
			serveMetrics(w); return
		}
		clientIP,_,_:=net.SplitHostPort(r.RemoteAddr)
		if cfg.Privacy=="local"&&clientIP!="127.0.0.1"&&clientIP!="::1" {
			Log.Req(WARN,"server","Non-local denied",reqID,map[string]interface{}{"ip":clientIP})
			serveError(w,cfg,http.StatusForbidden); return }
		reqHost:=r.Host
		if h,_,err:=net.SplitHostPort(reqHost);err==nil{reqHost=h}
		if reqHost!=cfg.Domain&&reqHost!="localhost"&&reqHost!="127.0.0.1"&&reqHost!="::1"&&reqHost!="" {
			serveError(w,cfg,http.StatusNotFound); return }
		for _,rule:=range cfg.Redirects {
			if rule.Re!=nil&&rule.Re.MatchString(r.URL.Path) {
				http.Redirect(w,r,rule.Re.ReplaceAllString(r.URL.Path,rule.To),rule.Code); return } }
		var matchedLoc *LocationConfig; var matchedPrefix string
		if len(cfg.Locations)>0 {
			keys:=make([]string,0,len(cfg.Locations))
			for k:=range cfg.Locations{keys=append(keys,k)}
			sort.Slice(keys,func(i,j int)bool{return len(keys[i])>len(keys[j])})
			for _,prefix:=range keys {
				if strings.HasPrefix(r.URL.Path,prefix){matchedLoc=cfg.Locations[prefix];matchedPrefix=prefix;break} } }
		var pool *UpstreamPool
		if matchedLoc!=nil&&matchedLoc.Pool!=nil { pool=matchedLoc.Pool
		} else if matchedLoc==nil&&cfg.Upstream!=nil { pool=cfg.Upstream }
		if pool!=nil&&len(pool.Nodes)>0 {
			if matchedLoc!=nil&&matchedLoc.StripPrefix&&matchedPrefix!="" {
				r2:=r.Clone(r.Context()); r2.URL.Path=strings.TrimPrefix(r.URL.Path,matchedPrefix)
				if r2.URL.Path==""{r2.URL.Path="/"}; r=r2 }
			ProxyRequest(w,r,pool,cfg); return }
		folder:=cfg.Folder
		if matchedLoc!=nil&&matchedLoc.Folder!=""{folder=matchedLoc.Folder}
		serveStatic(w,r,cfg,folder)
	}
}

func serveStatic(w http.ResponseWriter, r *http.Request, cfg *ServerConfig, folder string) {
	reqID:=r.Header.Get("X-Request-ID")
	folderAbs,err:=SafePath(CorePath,folder)
	if err!=nil{Log.Req(ERROR,"server","Static folder error",reqID,map[string]interface{}{"err":err.Error()});serveError(w,cfg,http.StatusForbidden);return}
	urlPath:=filepath.Clean(r.URL.Path); if urlPath=="/"||urlPath=="."{urlPath="/index.html"}
	filePath,err:=SafePath(folderAbs,urlPath)
	if err!=nil{Log.Req(WARN,"server","Traversal blocked",reqID,map[string]interface{}{"path":r.URL.Path});serveError(w,cfg,http.StatusForbidden);return}
	info,err:=os.Stat(filePath)
	if os.IsNotExist(err){serveError(w,cfg,http.StatusNotFound);return}
	if err!=nil{serveError(w,cfg,http.StatusInternalServerError);return}
	if info.IsDir() {
		indexPath,err2:=SafePath(filePath,"index.html"); if err2!=nil{serveError(w,cfg,http.StatusForbidden);return}
		if _,e:=os.Stat(indexPath);os.IsNotExist(e){serveError(w,cfg,http.StatusNotFound);return}
		filePath=indexPath }
	http.ServeFile(w,r,filePath)
}

func serveError(w http.ResponseWriter, cfg *ServerConfig, code int) {
	errPath,err:=SafePath(CorePath,fmt.Sprintf("%s/%d.html",cfg.ErrorFolder,code))
	if err!=nil{http.Error(w,fmt.Sprintf("Veno/3.0 — %d",code),code);return}
	content,err:=os.ReadFile(errPath)
	if err!=nil{http.Error(w,fmt.Sprintf("Veno/3.0 — %d",code),code);return}
	w.Header().Set("Content-Type","text/html; charset=utf-8"); w.WriteHeader(code); w.Write(content)
}

func serveMetrics(w http.ResponseWriter) {
	cache:=map[string]interface{}{"status":"disabled"}
	if GlobalCache!=nil{cache=GlobalCache.Stats()}
	data,_:=json.Marshal(map[string]interface{}{
		"timestamp":time.Now().UTC().Format(time.RFC3339),
		"app":AppMeta.Name,"version":AppMeta.Version,"env":AppMeta.Env,
		"cache":cache,"servers":len(Configs)})
	w.Header().Set("Content-Type","application/json"); w.Header().Set("Cache-Control","no-store")
	w.WriteHeader(http.StatusOK); w.Write(data)
}
