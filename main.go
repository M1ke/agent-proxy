// Command agent-proxy records a browsing session through a local MITM proxy
// in a form an agent can read to understand -- and later automate -- a web
// task flow.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/m1ke/agent-proxy/internal/ca"
	"github.com/m1ke/agent-proxy/internal/control"
	"github.com/m1ke/agent-proxy/internal/filter"
	"github.com/m1ke/agent-proxy/internal/proxy"
	"github.com/m1ke/agent-proxy/internal/record"
	"github.com/m1ke/agent-proxy/internal/redact"
)

// version is overridden at build time: -ldflags "-X main.version=..."
var version = "0.1.0"

// controlHost is intercepted by the proxy and never resolved or forwarded.
const controlHost = "proxy.note"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "record":
		err = cmdRecord(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("agent-proxy", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "agent-proxy: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-proxy:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `agent-proxy -- record a browsing session for an agent to read

  agent-proxy record [flags]   start the recording proxy
  agent-proxy ca [--export F]  show or copy the CA certificate
  agent-proxy version

Run "agent-proxy record -h" for flags.
`)
}

func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agent-proxy"), nil
}

func cmdCA(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ExitOnError)
	export := fs.String("export", "", "copy the CA certificate to this path")
	fs.Parse(args)

	dir, err := stateDir()
	if err != nil {
		return err
	}
	authority, err := ca.Load(dir)
	if err != nil {
		return err
	}
	if *export != "" {
		if err := os.WriteFile(*export, authority.PEM(), 0o644); err != nil {
			return err
		}
		fmt.Println(*export)
		return nil
	}
	fmt.Println(authority.CertPath())
	return nil
}

func cmdRecord(args []string) error {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	port := fs.Int("port", 8080, "port to listen on")
	host := fs.String("host", "127.0.0.1", "address to listen on")
	dir := fs.String("dir", "recordings", "directory to write sessions into")
	name := fs.String("name", "", "optional session name, appended to the directory")
	filters := fs.String("filters", "", "path to a filter override file (default ~/.agent-proxy/filters.json)")
	noFilter := fs.Bool("no-filter", false, "record everything, including static assets and analytics")
	quiet := fs.Bool("quiet", false, "suppress the live console summary")
	fs.Parse(args)

	state, err := stateDir()
	if err != nil {
		return err
	}
	authority, err := ca.Load(state)
	if err != nil {
		return err
	}

	filterPath, optional := *filters, false
	if filterPath == "" {
		filterPath, optional = filepath.Join(state, "filters.json"), true
	}
	rules, err := filter.Load(filterPath, optional)
	if err != nil {
		return fmt.Errorf("loading filters from %s: %w", filterPath, err)
	}

	sessionDir := filepath.Join(*dir, sessionName(*name))
	rec, err := record.New(sessionDir, *quiet)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	mode := "default rules"
	if *noFilter {
		mode = "disabled"
	}

	ctrl := control.New(rec, controlHost, authority.CertPath(), cancel)
	p := proxy.New(proxy.Options{
		CA:          authority,
		Filter:      filter.New(rules, *noFilter),
		Redactor:    redact.New(rules.RedactKeys, rules.AllowKeys),
		Recorder:    rec,
		Control:     ctrl,
		ControlHost: controlHost,
	})

	srv := &http.Server{Addr: addr, Handler: p}
	errs := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errs <- err
		}
	}()

	rec.Write(&record.Entry{
		Type:      record.TypeSessionStart,
		Version:   version,
		Listen:    addr,
		Filtering: mode,
	})
	if !*quiet {
		printSetup(addr, authority.CertPath(), rec.Path())
	}

	select {
	case err := <-errs:
		rec.Close()
		return err
	case <-ctx.Done():
	}

	rec.Close()
	shutdownCtx, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	srv.Shutdown(shutdownCtx)
	return nil
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sessionName(name string) string {
	stamp := time.Now().Format("20060102-150405")
	if name == "" {
		return stamp
	}
	clean := strings.Trim(unsafeName.ReplaceAllString(name, "-"), "-")
	if clean == "" {
		return stamp
	}
	return stamp + "-" + clean
}

func printSetup(addr, caPath, transcript string) {
	fmt.Printf(`
agent-proxy %s -- recording

  Proxy       %s
  CA cert     %s
  Transcript  %s

Firefox setup (use a separate profile so this CA is not trusted in your
everyday browsing -- run "firefox -P" or open about:profiles):

  1. Settings > Privacy & Security > Certificates > View Certificates...
     > Authorities > Import... and choose:
         %s
     Tick "Trust this CA to identify websites".

  2. Settings > Network Settings > Settings...
     Choose "Manual proxy configuration".
         HTTP Proxy  %s
         Port        %s
     Tick "Also use this proxy for HTTPS".
     Clear the "No proxy for" box.

  3. Browse to the site and carry out the task you want automated.

While recording:

  %-28s add a note describing what you just did
  %-28s shorthand for the same thing
  %-28s finish the recording
  %-28s the same UI, if the browser will not accept the
                               made-up hostname above

  Ctrl-C also finishes the recording.

`, version, addr, caPath, transcript, caPath,
		hostOf(addr), portOf(addr),
		"http://"+controlHost+"/",
		"http://"+controlHost+"/signed%20in",
		"http://"+controlHost+"/stop",
		"http://"+addr+"/")
}

func hostOf(addr string) string {
	h, _, _ := strings.Cut(addr, ":")
	return h
}

func portOf(addr string) string {
	_, p, _ := strings.Cut(addr, ":")
	return p
}
