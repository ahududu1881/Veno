//go:build windows
package main
type VenoPlugin    struct{ Name, Version, Path string }
type PluginRegistry struct{}
var GlobalPlugins = &PluginRegistry{}
func initPlugins() { Log.Warn("plugin","Rust plugins not supported on Windows. Use WSL2.",nil) }
func (r *PluginRegistry) RunOnRequest(method,path,headers string) int { return 0 }
func UnloadAllPlugins() {}
