// main.go — Veno V3.0 | Entry Point & Orchestrator
package main

import (
	"context"; "fmt"; "net/http"; "os"; "os/signal"; "path/filepath"; "sync"; "syscall"; "time"
)

func main() {
	initLogger("veno",filepath.Join(".","logs"),false)
	initConfig()
	debug:=AppMeta.LogLevel=="debug"
	initLogger(AppMeta.Name,filepath.Join(CorePath,"logs"),debug)
	Log.Info("runtime","Veno Enterprise starting",map[string]interface{}{
		"app":AppMeta.Name,"version":AppMeta.Version,"env":AppMeta.Env,
		"servers":len(Configs),"root":CorePath})
	initCache(0,0)
	warden:=newMemoryWarden(0,GlobalCache); warden.Start(); defer warden.Stop()
	startHealthChecks(Configs)
	initPlugins(); defer UnloadAllPlugins()
	var wg sync.WaitGroup; var mu sync.Mutex; var servers []*http.Server
	for _,cfg:=range Configs {
		cfg:=cfg
		var wafEngine *WAFEngine; if cfg.WAF.Enabled{wafEngine=NewWAFEngine(cfg.WAF)}
		mux:=http.NewServeMux(); mux.Handle("/",buildChain(cfg,wafEngine))
		srv:=&http.Server{
			Addr:":"+cfg.Port,Handler:mux,
			ReadTimeout:time.Duration(Timeouts.Read)*time.Second,ReadHeaderTimeout:10*time.Second,
			WriteTimeout:time.Duration(Timeouts.Write)*time.Second,IdleTimeout:time.Duration(Timeouts.Idle)*time.Second,
			MaxHeaderBytes:1<<20}
		mu.Lock(); servers=append(servers,srv); mu.Unlock()
		wg.Add(1)
		go func(s *http.Server, c *ServerConfig) {
			defer wg.Done()
			Log.Info("runtime","Server listening",map[string]interface{}{
				"id":c.ID,"port":c.Port,"domain":c.Domain,"tls":c.TLS.Enabled,
				"waf":c.WAF.Enabled,"gzip":c.EnableGzip,"privacy":c.Privacy})
			var err error
			if c.TLS.Enabled {
				cert,e1:=SafePath(CorePath,c.TLS.Cert); key,e2:=SafePath(CorePath,c.TLS.Key)
				if e1!=nil||e2!=nil{Log.Fatal("runtime","TLS path error",
					map[string]interface{}{"cert_err":fmt.Sprintf("%v",e1),"key_err":fmt.Sprintf("%v",e2)})}
				err=s.ListenAndServeTLS(cert,key)
			} else { err=s.ListenAndServe() }
			if err!=nil&&err!=http.ErrServerClosed {
				Log.Error("runtime","Server error",map[string]interface{}{"id":c.ID,"port":c.Port,"err":err.Error()}) }
		}(srv,cfg)
	}
	quit:=make(chan os.Signal,1); signal.Notify(quit,syscall.SIGINT,syscall.SIGTERM)
	sig:=<-quit
	Log.Info("runtime","Shutting down gracefully",map[string]interface{}{"signal":sig.String()})
	ctx,cancel:=context.WithTimeout(context.Background(),time.Duration(Timeouts.Drain)*time.Second)
	defer cancel()
	mu.Lock()
	for _,srv:=range servers { if err:=srv.Shutdown(ctx);err!=nil{
		Log.Error("runtime","Shutdown error",map[string]interface{}{"err":err.Error()})} }
	mu.Unlock()
	wg.Wait(); Log.Info("runtime","All servers drained. Goodbye.",nil); Log.Close()
}
