// plugin.go — Veno V3.0 | Rust Hot-Reload Plugin System
// Linux/macOS only. Windows: see plugin_windows.go stubs.

//go:build !windows

package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
typedef const char* (*fn_name)();
typedef const char* (*fn_version)();
typedef int  (*fn_init)();
typedef void (*fn_destroy)();
typedef int  (*fn_on_request)(const char*, const char*, const char*);
void*       vdlopen (const char* p) { return dlopen(p, RTLD_NOW|RTLD_LOCAL); }
void*       vdlsym  (void* h, const char* s) { return dlsym(h, s); }
int         vdlclose(void* h) { return dlclose(h); }
const char* vdlerror() { return dlerror(); }
const char* vcall_name   (void* f) { return ((fn_name)f)(); }
const char* vcall_version(void* f) { return ((fn_version)f)(); }
int         vcall_init   (void* f) { return ((fn_init)f)(); }
void        vcall_destroy(void* f) { ((fn_destroy)f)(); }
int         vcall_request(void* f, const char* m, const char* p, const char* h) {
    return ((fn_on_request)f)(m, p, h); }
*/
import "C"

import (
	"bufio"; "fmt"; "os"; "path/filepath"; "strings"; "sync"; "unsafe"
	"github.com/fsnotify/fsnotify"
)

type VenoPlugin struct {
	Name, Version, Path string
	handle    unsafe.Pointer; fnRequest unsafe.Pointer; fnDestroy unsafe.Pointer
}
type PluginRegistry struct{ mu sync.RWMutex; plugins []*VenoPlugin }
var GlobalPlugins = &PluginRegistry{}

func loadPlugin(soPath string) (*VenoPlugin, error) {
	cs:=C.CString(soPath); defer C.free(unsafe.Pointer(cs))
	h:=C.vdlopen(cs); if h==nil{return nil,fmt.Errorf("dlopen %q: %s",soPath,C.GoString(C.vdlerror()))}
	sym:=func(name string)(unsafe.Pointer,error){
		cs:=C.CString(name); defer C.free(unsafe.Pointer(cs))
		p:=C.vdlsym(h,cs); if p==nil{return nil,fmt.Errorf("symbol %q missing",name)}; return p,nil}
	fnName,err:=sym("veno_plugin_name"); if err!=nil{C.vdlclose(h);return nil,err}
	fnVer,err:=sym("veno_plugin_version"); if err!=nil{C.vdlclose(h);return nil,err}
	fnInit,err:=sym("veno_init"); if err!=nil{C.vdlclose(h);return nil,err}
	fnReq,err:=sym("veno_on_request"); if err!=nil{C.vdlclose(h);return nil,err}
	fnDest,err:=sym("veno_destroy"); if err!=nil{C.vdlclose(h);return nil,err}
	if rc:=C.vcall_init(fnInit);rc!=0{C.vdlclose(h);return nil,fmt.Errorf("veno_init returned %d",int(rc))}
	return &VenoPlugin{Name:C.GoString(C.vcall_name(fnName)),Version:C.GoString(C.vcall_version(fnVer)),
		Path:soPath,handle:h,fnRequest:fnReq,fnDestroy:fnDest},nil
}
func (p *VenoPlugin) unload() {
	if p.fnDestroy!=nil{C.vcall_destroy(p.fnDestroy)}; if p.handle!=nil{C.vdlclose(p.handle)} }
func (r *PluginRegistry) Register(p *VenoPlugin) {
	r.mu.Lock(); defer r.mu.Unlock()
	for i,ex:=range r.plugins { if ex.Path==p.Path{ex.unload();r.plugins[i]=p
		Log.Info("plugin",fmt.Sprintf("Hot-swapped: %s v%s",p.Name,p.Version),nil);return} }
	r.plugins=append(r.plugins,p)
	Log.Info("plugin",fmt.Sprintf("Loaded: %s v%s",p.Name,p.Version),nil)
}
func (r *PluginRegistry) RunOnRequest(method,path,headers string) int {
	r.mu.RLock(); defer r.mu.RUnlock()
	cm:=C.CString(method);defer C.free(unsafe.Pointer(cm))
	cp:=C.CString(path);defer C.free(unsafe.Pointer(cp))
	ch:=C.CString(headers);defer C.free(unsafe.Pointer(ch))
	for _,p:=range r.plugins {
		if rc:=C.vcall_request(p.fnRequest,cm,cp,ch);rc!=0 {
			Log.Warn("plugin",fmt.Sprintf("%s blocked request",p.Name),map[string]interface{}{"path":path}); return int(rc) } }
	return 0
}
func initPlugins() {
	dir,err:=SafePath(CorePath,"plugins"); if err!=nil{Log.Warn("plugin","Cannot resolve plugins dir",map[string]interface{}{"err":err.Error()});return}
	os.MkdirAll(dir,0755)
	entries,_:=os.ReadDir(dir)
	for _,e:=range entries {
		if e.IsDir()||!strings.HasSuffix(e.Name(),".so"){continue}
		p,err:=loadPlugin(filepath.Join(dir,e.Name()))
		if err!=nil{Log.Error("plugin","Startup load failed",map[string]interface{}{"err":err.Error()});continue}
		GlobalPlugins.Register(p) }
	go watchPlugins(dir)
}
func watchPlugins(dir string) {
	w,err:=fsnotify.NewWatcher(); if err!=nil{Log.Error("plugin","Watcher failed",map[string]interface{}{"err":err.Error()});return}
	defer w.Close(); w.Add(dir)
	Log.Info("plugin","Watching plugins/ for Rust sources",map[string]interface{}{"dir":dir})
	for { select {
		case ev,ok:=<-w.Events:
			if !ok{return}
			if (ev.Op&fsnotify.Create!=0||ev.Op&fsnotify.Write!=0)&&strings.HasSuffix(ev.Name,".rs"){handleNewRust(ev.Name,dir)}
		case err,ok:=<-w.Errors:
			if !ok{return}; Log.Warn("plugin","Watcher error",map[string]interface{}{"err":err.Error()}) } }
}
func handleNewRust(rsPath,dir string) {
	base:=filepath.Base(rsPath)
	fmt.Printf("\n\033[36m[PLUGIN]\033[0m Yeni Rust kaynağı: %s\n",base)
	fmt.Printf("         Sunucuya entegre et? [e/H]: ")
	ans,_:=bufio.NewReader(os.Stdin).ReadString('\n')
	ans=strings.TrimSpace(strings.ToLower(ans))
	if ans!="e"&&ans!="evet"&&ans!="y"&&ans!="yes"{Log.Info("plugin","Hot-reload reddedildi",nil);return}
	soPath,err:=compileRust(rsPath,dir)
	if err!=nil{Log.Error("plugin","Derleme hatası",map[string]interface{}{"err":err.Error()});fmt.Printf("\033[31m[PLUGIN]\033[0m Hata: %v\n",err);return}
	p,err:=loadPlugin(soPath)
	if err!=nil{Log.Error("plugin","Yükleme hatası",map[string]interface{}{"err":err.Error()});fmt.Printf("\033[31m[PLUGIN]\033[0m Yüklenemedi: %v\n",err);return}
	GlobalPlugins.Register(p); fmt.Printf("\033[32m[PLUGIN]\033[0m Aktif: %s v%s\n",p.Name,p.Version)
}
func compileRust(rsPath,outDir string) (string,error) {
	base:=strings.TrimSuffix(filepath.Base(rsPath),".rs"); soPath:=filepath.Join(outDir,"lib"+base+".so")
	cargoToml:=filepath.Join(filepath.Dir(rsPath),"Cargo.toml")
	if _,err:=os.Stat(cargoToml);err==nil {
		cmd:=newSafeCmd("cargo","build","--release","--manifest-path",cargoToml)
		if out,err:=cmd.CombinedOutput();err!=nil{return "",fmt.Errorf("cargo: %s",out)}
		release:=filepath.Join(filepath.Dir(rsPath),"target","release","lib"+base+".so")
		if err:=os.Rename(release,soPath);err!=nil{return "",fmt.Errorf("move: %w",err)}
		return soPath,nil }
	cmd:=newSafeCmd("rustc","--crate-type=cdylib","-O","-o",soPath,rsPath)
	if out,err:=cmd.CombinedOutput();err!=nil{return "",fmt.Errorf("rustc: %s",out)}
	return soPath,nil
}
func UnloadAllPlugins() {
	GlobalPlugins.mu.Lock(); defer GlobalPlugins.mu.Unlock()
	for _,p:=range GlobalPlugins.plugins{Log.Info("plugin","Unloading: "+p.Name,nil);p.unload()}
	GlobalPlugins.plugins=nil
}
