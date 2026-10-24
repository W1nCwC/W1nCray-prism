// W1nCray-prism is the second proxy kernel of the W1nCray panel system
// (GPL-3.0-or-later). The W1nCray agent drives it over a local socket.
//
//	w1ncray-prism run [--socket unix:/run/W1nCray-prism/prism.sock] [--state /var/lib/W1nCray-prism]
//	w1ncray-prism check -c config.json
//	w1ncray-prism version
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/W1nCwC/W1nCray-prism/engine"
	"github.com/W1nCwC/W1nCray-prism/gate"
	"github.com/W1nCwC/W1nCray-prism/ipc"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "version":
		fmt.Printf("W1nCray-prism v%s (core %s, api %d)\n", engine.Version, engine.CoreVersion, engine.APIVersion)
	case "check":
		check(os.Args[2:])
	case "run":
		run(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: w1ncray-prism run|check|version")
	os.Exit(2)
}

func check(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	path := fs.String("c", "", "config file")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	e, err := engine.New(os.TempDir(), gate.New())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := e.Check(raw); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("OK")
}

func run(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	socket := fs.String("socket", "unix:/run/W1nCray-prism/prism.sock", "control socket: unix:<path> or tcp:<host:port> (tests)")
	state := fs.String("state", "/var/lib/W1nCray-prism", "state directory")
	_ = fs.Parse(args)

	e, err := engine.New(*state, gate.Default)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	e.Restore()
	ln, err := listen(*socket)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: ipc.New(e, gate.Default), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Printf("W1nCray-prism v%s listening on %s\n", engine.Version, *socket)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = e.Close()
}

func listen(spec string) (net.Listener, error) {
	kind, addr, ok := strings.Cut(spec, ":")
	if !ok {
		return nil, fmt.Errorf("--socket must be unix:<path> or tcp:<host:port>")
	}
	switch kind {
	case "unix":
		if err := os.MkdirAll(filepath.Dir(addr), 0o700); err != nil {
			return nil, err
		}
		_ = os.Remove(addr)
		ln, err := net.Listen("unix", addr)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(addr, 0o600); err != nil {
			_ = ln.Close()

			return nil, err
		}

		return ln, nil
	case "tcp":
		return net.Listen("tcp", addr)
	default:
		return nil, fmt.Errorf("unknown socket kind %q", kind)
	}
}
