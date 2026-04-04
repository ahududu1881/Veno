// logger.go — Veno V3.0 | Structured JSON Logging
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Level string
const (
	DEBUG Level = "DEBUG"; INFO Level = "INFO"
	WARN  Level = "WARN";  ERROR Level = "ERROR"; FATAL Level = "FATAL"
)

type LogEntry struct {
	Time    string                 `json:"@timestamp"`
	Level   Level                  `json:"level"`
	Service string                 `json:"service,omitempty"`
	Module  string                 `json:"module"`
	ReqID   string                 `json:"request_id,omitempty"`
	Msg     string                 `json:"message"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

type Logger struct {
	mu sync.Mutex; writers []io.Writer; min Level
	service, date, dir string; file *os.File
}

var Log *Logger

func initLogger(service, dir string, debug bool) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] log dir: %v\n", err)
	}
	l := &Logger{service: service, dir: dir, min: INFO}
	if debug { l.min = DEBUG }
	l.rotate()
	Log = l
}

func (l *Logger) rotate() {
	today := time.Now().Format("2006-01-02")
	if l.date == today && l.file != nil { return }
	if l.file != nil { l.file.Sync(); l.file.Close(); l.file = nil }
	f, err := os.OpenFile(filepath.Join(l.dir, "veno_"+today+".jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil { l.writers = []io.Writer{os.Stdout}; return }
	l.file = f; l.date = today; l.writers = []io.Writer{os.Stdout, f}
}

func (l *Logger) emit(lv Level, module, msg, reqID string, fields map[string]interface{}) {
	if l.min == INFO && lv == DEBUG { return }
	l.mu.Lock(); defer l.mu.Unlock()
	if today := time.Now().Format("2006-01-02"); today != l.date { l.rotate() }
	e := LogEntry{Time: time.Now().UTC().Format(time.RFC3339Nano),
		Level: lv, Service: l.service, Module: module, ReqID: reqID, Msg: msg, Fields: fields}
	data, _ := json.Marshal(e)
	line := string(data) + "\n"
	for _, w := range l.writers { fmt.Fprint(w, line) }
}

func (l *Logger) Debug(mod, msg string, f ...map[string]interface{}) { l.emit(DEBUG, mod, msg, "", first(f)) }
func (l *Logger) Info(mod, msg string, f ...map[string]interface{})  { l.emit(INFO, mod, msg, "", first(f)) }
func (l *Logger) Warn(mod, msg string, f ...map[string]interface{})  { l.emit(WARN, mod, msg, "", first(f)) }
func (l *Logger) Error(mod, msg string, f ...map[string]interface{}) { l.emit(ERROR, mod, msg, "", first(f)) }
func (l *Logger) Fatal(mod, msg string, f ...map[string]interface{}) {
	l.emit(FATAL, mod, msg, "", first(f)); l.Close(); os.Exit(1)
}
func (l *Logger) Req(lv Level, mod, msg, reqID string, fields map[string]interface{}) {
	l.emit(lv, mod, msg, reqID, fields)
}
func (l *Logger) Close() {
	l.mu.Lock(); defer l.mu.Unlock()
	if l.file != nil { l.file.Sync(); l.file.Close(); l.file = nil }
}
func first(f []map[string]interface{}) map[string]interface{} {
	if len(f) == 0 { return nil }; return f[0]
}
