// Package cli implements the agentleaks command line.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Arthur031221/agentleaks/internal/fix"
	"github.com/Arthur031221/agentleaks/internal/guard"
	"github.com/Arthur031221/agentleaks/internal/output"
	"github.com/Arthur031221/agentleaks/internal/rules"
	"github.com/Arthur031221/agentleaks/internal/scan"
	"github.com/Arthur031221/agentleaks/internal/sources"
	"github.com/Arthur031221/agentleaks/internal/verify"
)

// Version is set from the build by main.
var Version = "dev"

// Exit codes.
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitError    = 2
)

type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	isTTY  func(io.Writer) bool
}

// Main runs the CLI and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr, isTTY: isTerminal}
	if len(args) == 0 {
		args = []string{"scan"}
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return a.scan(rest, false, false)
	case "report":
		return a.scan(rest, true, false)
	case "verify":
		return a.scan(rest, false, true)
	case "fix":
		return a.fix(rest)
	case "guard":
		return a.guard(rest)
	case "hook":
		return a.hook(rest)
	case "rules":
		return a.rules(rest)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "agentleaks %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		return ExitClean
	case "help", "--help", "-h":
		a.usage(stdout)
		return ExitClean
	default:
		if strings.HasPrefix(cmd, "-") {
			// Bare flags mean scan, for example `agentleaks --json`.
			return a.scan(args, false, false)
		}
		fmt.Fprintf(stderr, "agentleaks: unknown command %q\n\n", cmd)
		a.usage(stderr)
		return ExitError
	}
}

func (a *app) usage(w io.Writer) {
	fmt.Fprint(w, `agentleaks finds, redacts and blocks API keys in AI coding tool history.

Usage:
  agentleaks [scan] [flags] [path ...]   find secrets in every supported tool, or in the given paths
  agentleaks fix [flags]                 redact secrets in place (dry run unless --yes)
  agentleaks guard [flags]               install hooks that stop agents from reading secret files
  agentleaks verify [flags]              scan, then check which keys are still live (sends keys to their providers)
  agentleaks report --json | --sarif     scan and write a machine readable report
  agentleaks rules                       list detection rules
  agentleaks hook <tool> <event>         hook entry point, called by the tools themselves
  agentleaks version

Run any command with --help for its flags.
Exit codes: 0 nothing found, 1 secrets found, 2 error.
`)
}

// scanFlags are shared by scan, report, verify and fix.
type scanFlags struct {
	home        string
	tools       string
	repos       string
	depth       int
	workers     int
	rule        string
	minSeverity string
	quiet       bool
	includeCred bool
}

func (a *app) addScanFlags(fs *flag.FlagSet, sf *scanFlags) {
	fs.StringVar(&sf.home, "home", "", "home directory to scan (default: current user, or $AGENTLEAKS_HOME)")
	fs.StringVar(&sf.tools, "tool", "", "comma separated tool ids to scan (default: all found). See `agentleaks rules --tools`")
	fs.StringVar(&sf.repos, "repos", "", "comma separated directories to search for per-project files (default: common project folders under home)")
	fs.IntVar(&sf.depth, "depth", 4, "directory depth for the per-project search")
	fs.IntVar(&sf.workers, "workers", runtime.NumCPU(), "parallel files")
	fs.StringVar(&sf.rule, "rule", "", "comma separated rule ids to report (default: all)")
	fs.StringVar(&sf.minSeverity, "min-severity", "low", "lowest severity to report: high, medium or low")
	fs.BoolVar(&sf.quiet, "quiet", false, "no progress output")
	fs.BoolVar(&sf.includeCred, "include-credential-stores", false, "also report the tools' own credential files")
}

func (sf scanFlags) env() sources.Env {
	home := sf.home
	if home == "" {
		home = os.Getenv("AGENTLEAKS_HOME")
	}
	e := sources.Env{Home: home, RepoDepth: sf.depth}
	if sf.repos != "" {
		e.RepoRoots = splitList(sf.repos)
	}
	return e.Fill()
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

type scanResult struct {
	findings []scan.Finding
	stats    scan.Stats
	statuses []sources.Status
	targets  []sources.Target
	env      sources.Env
}

func (a *app) runScan(ctx context.Context, sf scanFlags, paths []string, set *rules.Set) (*scanResult, error) {
	env := sf.env()
	res := &scanResult{env: env}
	opts := scan.Options{Rules: set, Workers: sf.workers, SkipCredentialStores: !sf.includeCred}
	if len(paths) > 0 {
		for _, p := range paths {
			fs, st, err := scan.Path(ctx, opts, p)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			res.findings = append(res.findings, fs...)
			res.stats.Files += st.Files
			res.stats.Bytes += st.Bytes
			res.stats.Duration += st.Duration
			res.stats.Errors = append(res.stats.Errors, st.Errors...)
		}
		scan.Sort(res.findings)
	} else {
		var only []string
		if sf.tools != "" {
			only = splitList(sf.tools)
			for _, id := range only {
				if _, ok := sources.Lookup(id); !ok {
					return nil, fmt.Errorf("unknown tool %q, run `agentleaks rules --tools` for the list", id)
				}
			}
		}
		res.targets, res.statuses = sources.Discover(env, only)
		if !sf.quiet {
			a.progressStart(res)
		}
		res.findings, res.stats = scan.Targets(ctx, opts, res.targets)
	}
	res.findings = filterFindings(res.findings, sf)
	return res, nil
}

func (a *app) progressStart(res *scanResult) {
	var names []string
	var bytes int64
	for _, s := range res.statuses {
		if s.Found {
			names = append(names, s.Name)
			bytes += s.Bytes
		}
	}
	if len(names) == 0 {
		return
	}
	fmt.Fprintf(a.stderr, "Scanning %d files (%s) from %s\n", len(res.targets), output.Bytes(bytes), strings.Join(names, ", "))
}

func filterFindings(fs []scan.Finding, sf scanFlags) []scan.Finding {
	want := map[string]bool{}
	for _, r := range splitList(sf.rule) {
		want[r] = true
	}
	minSev := severityRank(sf.minSeverity)
	out := fs[:0]
	for _, f := range fs {
		if len(want) > 0 && !want[f.RuleID] {
			continue
		}
		if severityRank(f.Severity) < minSev {
			continue
		}
		out = append(out, f)
	}
	return out
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	default:
		return 1
	}
}

func (a *app) scan(args []string, reportMode, verifyMode bool) int {
	name := "scan"
	if reportMode {
		name = "report"
	}
	if verifyMode {
		name = "verify"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var sf scanFlags
	a.addScanFlags(fs, &sf)
	var (
		asJSON  = fs.Bool("json", reportMode, "write a JSON report to stdout")
		asSARIF = fs.Bool("sarif", false, "write a SARIF 2.1.0 report to stdout")
		outFile = fs.String("o", "", "write the report to this file instead of stdout")
		all     = fs.Bool("all", false, "one table row per occurrence instead of per secret per file")
		noColor = fs.Bool("no-color", false, "disable ANSI colours")
		doVer   = fs.Bool("verify", verifyMode, "check which keys are still live by calling each provider's read-only endpoint")
		yes     = fs.Bool("yes", false, "skip the verification consent prompt")
		exit0   = fs.Bool("exit-zero", false, "exit 0 even when secrets are found")
	)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "Usage: agentleaks %s [flags] [path ...]\n\n", name)
		switch name {
		case "scan":
			fmt.Fprintln(a.stderr, "Find secrets in every supported AI coding tool's local history, or in the given files and directories.")
		case "report":
			fmt.Fprintln(a.stderr, "Scan and write a JSON (default) or SARIF report.")
		case "verify":
			fmt.Fprintln(a.stderr, "Scan, then send each found key to its own provider's read-only endpoint to see whether it is still live.")
		}
		fmt.Fprintln(a.stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		return ExitError
	}
	set, err := rules.Load()
	if err != nil {
		fmt.Fprintln(a.stderr, "agentleaks:", err)
		return ExitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := a.runScan(ctx, sf, fs.Args(), set)
	if err != nil {
		fmt.Fprintln(a.stderr, "agentleaks:", err)
		return ExitError
	}
	if *doVer {
		if code := a.verifyFindings(ctx, res, set, *yes, sf.quiet); code != ExitClean {
			return code
		}
	}
	w := a.stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintln(a.stderr, "agentleaks:", err)
			return ExitError
		}
		defer f.Close()
		w = f
	}
	switch {
	case *asSARIF:
		if err := output.SARIF(w, res.findings, set, Version); err != nil {
			fmt.Fprintln(a.stderr, "agentleaks:", err)
			return ExitError
		}
	case *asJSON:
		rep := output.Report{
			Version: Version, GeneratedAt: time.Now().UTC(),
			Summary: output.Summarize(res.findings, res.stats),
			Tools:   res.statuses, Findings: res.findings, Errors: res.stats.Errors,
		}
		if err := output.JSON(w, rep); err != nil {
			fmt.Fprintln(a.stderr, "agentleaks:", err)
			return ExitError
		}
	default:
		a.printTable(w, res, output.TableOptions{
			Home: res.env.Home, All: *all, Verified: *doVer,
			Color: !*noColor && os.Getenv("NO_COLOR") == "" && a.isTTY(w),
		})
	}
	if *outFile != "" && !sf.quiet {
		fmt.Fprintf(a.stderr, "Wrote %s\n", *outFile)
	}
	if len(res.findings) > 0 && !*exit0 {
		return ExitFindings
	}
	return ExitClean
}

func (a *app) printTable(w io.Writer, res *scanResult, topts output.TableOptions) {
	if res.statuses != nil {
		found := 0
		for _, s := range res.statuses {
			if s.Found {
				found++
			}
		}
		if found == 0 {
			fmt.Fprintf(w, "No supported AI tool data found under %s.\n", res.env.Home)
			fmt.Fprintln(w, "Looked for: "+strings.Join(toolNames(), ", ")+".")
			fmt.Fprintln(w, "Point at a file or directory instead: agentleaks scan <path>")
			return
		}
	}
	output.Table(w, res.findings, topts)
	if len(res.findings) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, output.SummaryLine(res.findings, res.stats, res.statuses))
	if len(res.stats.Errors) > 0 {
		fmt.Fprintf(w, "%d files could not be read:\n", len(res.stats.Errors))
		for i, e := range res.stats.Errors {
			if i >= 5 {
				fmt.Fprintf(w, "  and %d more (see --json)\n", len(res.stats.Errors)-5)
				break
			}
			fmt.Fprintf(w, "  %s: %s\n", sources.Shorten(res.env.Home, e.Path), e.Err)
		}
	}
	if len(res.findings) > 0 && res.statuses != nil {
		fmt.Fprintln(w, "Next: `agentleaks fix` to redact (dry run), `agentleaks guard` to stop it happening again.")
	}
}

func toolNames() []string {
	var names []string
	for _, t := range sources.Registry {
		names = append(names, t.Name)
	}
	return names
}

// verifyFindings probes each distinct verifiable secret and annotates findings.
func (a *app) verifyFindings(ctx context.Context, res *scanResult, set *rules.Set, yes, quiet bool) int {
	type item struct {
		name   string
		secret string
	}
	items := map[string]item{}
	providers := map[string]bool{}
	for _, f := range res.findings {
		if f.Verify == "" || !verify.Supported(f.Verify) {
			continue
		}
		if _, ok := items[f.Fingerprint]; !ok {
			items[f.Fingerprint] = item{name: f.Verify, secret: f.Secret}
			providers[f.Verify] = true
		}
	}
	if len(items) == 0 {
		if !quiet {
			fmt.Fprintln(a.stderr, "Nothing to verify: no findings belong to a provider with a safe read-only endpoint.")
		}
		return ExitClean
	}
	names := make([]string, 0, len(providers))
	for p := range providers {
		names = append(names, p)
	}
	sort.Strings(names)
	fmt.Fprintln(a.stderr, verify.Notice)
	fmt.Fprintf(a.stderr, "%d distinct keys would be sent to: %s.\n", len(items), strings.Join(names, ", "))
	if !yes {
		if !a.isTTY(a.stderr) {
			fmt.Fprintln(a.stderr, "Not a terminal. Pass --yes to confirm.")
			return ExitError
		}
		fmt.Fprint(a.stderr, "Continue? [y/N] ")
		line, _ := bufio.NewReader(a.stdin).ReadString('\n')
		if l := strings.ToLower(strings.TrimSpace(line)); l != "y" && l != "yes" {
			fmt.Fprintln(a.stderr, "Aborted.")
			return ExitError
		}
	}
	prober := verify.New()
	results := map[string]verify.Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for fp, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(fp string, it item) {
			defer wg.Done()
			defer func() { <-sem }()
			r := prober.Probe(ctx, it.name, it.secret)
			mu.Lock()
			results[fp] = r
			mu.Unlock()
		}(fp, it)
	}
	wg.Wait()
	for i := range res.findings {
		if r, ok := results[res.findings[i].Fingerprint]; ok {
			res.findings[i].Status = string(r.Status)
			res.findings[i].StatusInfo = r.Detail
		}
	}
	return ExitClean
}

func (a *app) fix(args []string) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var sf scanFlags
	a.addScanFlags(fs, &sf)
	var (
		yes       = fs.Bool("yes", false, "apply the changes (default is a dry run)")
		noBackup  = fs.Bool("no-backup", false, "do not keep a copy of the original files")
		backupDir = fs.String("backup-dir", "", "where to keep originals (default ~/.agentleaks/backups/<timestamp>)")
		asJSON    = fs.Bool("json", false, "write results as JSON")
	)
	fs.Usage = func() {
		fmt.Fprintln(a.stderr, "Usage: agentleaks fix [flags] [path ...]")
		fmt.Fprintln(a.stderr, "\nReplace every secret with [REDACTED:<rule>] in place. JSONL records, JSON documents and SQLite rows stay valid.")
		fmt.Fprintln(a.stderr, "Originals are copied to the backup directory first. Dry run unless --yes.")
		fmt.Fprintln(a.stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		return ExitError
	}
	set, err := rules.Load()
	if err != nil {
		fmt.Fprintln(a.stderr, "agentleaks:", err)
		return ExitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := a.runScan(ctx, sf, fs.Args(), set)
	if err != nil {
		fmt.Fprintln(a.stderr, "agentleaks:", err)
		return ExitError
	}
	// Only files with findings are rewritten.
	byPath := map[string]sources.Target{}
	counts := map[string]int{}
	for _, f := range res.findings {
		counts[f.Path]++
		if _, ok := byPath[f.Path]; ok {
			continue
		}
		byPath[f.Path] = targetFor(res, f)
	}
	paths := make([]string, 0, len(byPath))
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	targets := make([]sources.Target, 0, len(paths))
	for _, p := range paths {
		targets = append(targets, byPath[p])
	}
	if len(targets) == 0 {
		if *asJSON {
			fmt.Fprintln(a.stdout, "[]")
		} else {
			fmt.Fprintln(a.stdout, "Nothing to fix.", output.SummaryLine(nil, res.stats, res.statuses))
		}
		return ExitClean
	}
	opts := fix.Options{
		Rules: set, DryRun: !*yes, NoBackup: *noBackup, BackupDir: *backupDir,
		Home: res.env.Home, IncludeCredentialStores: sf.includeCred,
	}
	results := fix.Run(ctx, opts, targets)
	if *asJSON {
		enc := jsonEncoder(a.stdout)
		if err := enc.Encode(results); err != nil {
			return ExitError
		}
	} else {
		a.printFixTable(res.env.Home, results, counts)
	}
	code := ExitClean
	total, files, kept := 0, 0, 0
	var backupRoot string
	for _, r := range results {
		if r.Error != "" {
			code = ExitError
		}
		if r.Redacted > 0 {
			total += r.Redacted
			files++
		}
		kept += r.Kept
		if r.Backup != "" && backupRoot == "" {
			backupRoot = opts.BackupDir
			if *backupDir != "" {
				backupRoot = *backupDir
			}
		}
	}
	if *asJSON {
		return code
	}
	fmt.Fprintln(a.stdout)
	if !*yes {
		fmt.Fprintf(a.stdout, "Dry run: %d secrets in %d files would be redacted. Re-run with --yes to apply.\n", total, files)
	} else {
		fmt.Fprintf(a.stdout, "Redacted %d secrets in %d files.\n", total, files)
		if backupRoot != "" {
			fmt.Fprintf(a.stdout, "Originals kept under %s (they still contain the secrets). Remove that directory once the tools still work.\n", backupRoot)
		}
	}
	if kept > 0 {
		fmt.Fprintf(a.stdout, "%d records were left untouched because redaction would have broken their JSON.\n", kept)
	}
	return code
}

func targetFor(res *scanResult, f scan.Finding) sources.Target {
	for _, t := range res.targets {
		if t.Path == f.Path {
			return t
		}
	}
	info, _ := os.Stat(f.Path)
	t := sources.Target{Tool: f.Tool, ToolName: f.ToolName, Label: f.Label, Kind: sources.KindForPath(f.Path), Path: f.Path, Credential: f.Credential}
	if info != nil {
		t.Size = info.Size()
		t.ModTime = info.ModTime()
	}
	return t
}

func (a *app) printFixTable(home string, results []fix.Result, counts map[string]int) {
	w := a.stdout
	fmt.Fprintf(w, "%-60s  %7s  %s\n", "FILE", "SECRETS", "ACTION")
	for _, r := range results {
		p := sources.Shorten(home, r.Path)
		if len(p) > 60 {
			p = "..." + p[len(p)-57:]
		}
		action := "would redact"
		switch {
		case r.Error != "":
			action = "error: " + r.Error
		case r.Skipped != "":
			action = "skipped: " + r.Skipped
		case !r.DryRun && r.Redacted > 0:
			action = "redacted"
		case r.Redacted == 0:
			action = "kept (redaction would break records)"
		}
		fmt.Fprintf(w, "%-60s  %7d  %s\n", p, counts[r.Path], action)
	}
}

func (a *app) guard(args []string) int {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var (
		tools     = fs.String("tool", "", "comma separated tools: "+strings.Join(guard.Tools(), ", ")+" (default: all that are installed)")
		uninstall = fs.Bool("uninstall", false, "remove the hooks instead")
		dryRun    = fs.Bool("dry-run", false, "show what would change without writing")
		force     = fs.Bool("force", false, "install even when the tool's config directory does not exist")
		binary    = fs.String("binary", "", "path to the agentleaks binary to reference (default: this executable)")
		home      = fs.String("home", "", "home directory (default: current user, or $AGENTLEAKS_HOME)")
		coverage  = fs.Bool("coverage", false, "print what each tool's hook system can and cannot block")
		asJSON    = fs.Bool("json", false, "write results as JSON")
	)
	fs.Usage = func() {
		fmt.Fprintln(a.stderr, "Usage: agentleaks guard [flags]")
		fmt.Fprintln(a.stderr, "\nInstall hooks so the agent is denied when it tries to read .env, key files, cloud credentials or the tools' own config.")
		fmt.Fprintln(a.stderr, "Claude Code also gets a PostToolUse hook that redacts secrets from tool output before they reach the transcript.")
		fmt.Fprintln(a.stderr, "\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		return ExitError
	}
	if *coverage {
		a.printCoverage()
		return ExitClean
	}
	h := *home
	if h == "" {
		h = os.Getenv("AGENTLEAKS_HOME")
	}
	opts := guard.InstallOptions{Home: h, Binary: *binary, DryRun: *dryRun, Force: *force}
	if *tools != "" {
		opts.Tools = splitList(*tools)
	}
	var results []guard.InstallResult
	if *uninstall {
		results = guard.Uninstall(opts)
	} else {
		results = guard.Install(opts)
	}
	if *asJSON {
		type row struct {
			Tool   string `json:"tool"`
			Path   string `json:"path"`
			Action string `json:"action"`
			Error  string `json:"error,omitempty"`
		}
		rows := make([]row, 0, len(results))
		for _, r := range results {
			e := ""
			if r.Err != nil {
				e = r.Err.Error()
			}
			rows = append(rows, row{r.Tool, r.Path, r.Action, e})
		}
		_ = jsonEncoder(a.stdout).Encode(rows)
	} else {
		code := ExitClean
		installed := 0
		for _, r := range results {
			line := fmt.Sprintf("%-12s %-18s %s", r.Tool, r.Action, sources.Shorten(h, r.Path))
			if r.Err != nil {
				line += ": " + r.Err.Error()
				code = ExitError
			}
			fmt.Fprintln(a.stdout, line)
			if r.Action == "installed" || r.Action == "already-installed" {
				installed++
			}
		}
		if !*uninstall && !*dryRun && installed > 0 {
			fmt.Fprintln(a.stdout, "\nRestart the tools to load the hooks. Try it: ask the agent to `cat .env`.")
			fmt.Fprintln(a.stdout, "Add your own paths, one glob per line, in ~/.agentleaks/guard-paths.txt.")
		}
		return code
	}
	for _, r := range results {
		if r.Err != nil {
			return ExitError
		}
	}
	return ExitClean
}

func (a *app) printCoverage() {
	w := a.stdout
	fmt.Fprintf(w, "%-12s %-34s %-9s %-10s %-12s %s\n", "TOOL", "CONFIG", "DENY-READ", "DENY-SHELL", "SCRUB-OUTPUT", "EVENTS")
	for _, c := range guard.CoverageTable() {
		fmt.Fprintf(w, "%-12s %-34s %-9s %-10s %-12s %s\n", c.Tool, c.ConfigPath, yn(c.DenyRead), yn(c.DenyShell), yn(c.ScrubOutput), strings.Join(c.Events, ", "))
	}
	fmt.Fprintln(w)
	for _, c := range guard.CoverageTable() {
		fmt.Fprintf(w, "%s: %s\n", c.Tool, c.Notes)
	}
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (a *app) hook(args []string) int {
	if len(args) != 2 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(a.stderr, "Usage: agentleaks hook <tool> <event>")
		fmt.Fprintln(a.stderr, "Reads the tool's hook payload from stdin and answers with that tool's deny protocol.")
		fmt.Fprintln(a.stderr, "Tools: "+strings.Join(guard.Tools(), ", ")+". This command is installed by `agentleaks guard`.")
		if len(args) == 2 {
			return ExitClean
		}
		return ExitError
	}
	return guard.Run(args[0], args[1], a.stdin, a.stdout, a.stderr)
}

func (a *app) rules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	asJSON := fs.Bool("json", false, "write as JSON")
	listTools := fs.Bool("tools", false, "list supported tools and the paths they are scanned at instead")
	fs.Usage = func() {
		fmt.Fprintln(a.stderr, "Usage: agentleaks rules [--json] [--tools]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitClean
		}
		return ExitError
	}
	if *listTools {
		if *asJSON {
			type pat struct {
				Path       string `json:"path"`
				Kind       string `json:"kind"`
				Label      string `json:"label"`
				Credential bool   `json:"credential_store,omitempty"`
				OS         string `json:"os,omitempty"`
			}
			type tool struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Paths []pat  `json:"paths"`
			}
			var out []tool
			for _, t := range sources.Registry {
				tt := tool{ID: t.ID, Name: t.Name}
				for _, p := range t.Patterns {
					tt.Paths = append(tt.Paths, pat{p.Display(), string(p.Kind), p.Label, p.Credential, strings.Join(p.OS, ",")})
				}
				out = append(out, tt)
			}
			_ = jsonEncoder(a.stdout).Encode(out)
			return ExitClean
		}
		for _, t := range sources.Registry {
			fmt.Fprintf(a.stdout, "%s (%s)\n", t.Name, t.ID)
			for _, p := range t.Patterns {
				extra := ""
				if len(p.OS) > 0 {
					extra = " [" + strings.Join(p.OS, ",") + "]"
				}
				if p.Credential {
					extra += " [credential store]"
				}
				fmt.Fprintf(a.stdout, "  %-70s %s%s\n", p.Display(), p.Label, extra)
			}
		}
		return ExitClean
	}
	set, err := rules.Load()
	if err != nil {
		fmt.Fprintln(a.stderr, "agentleaks:", err)
		return ExitError
	}
	if *asJSON {
		type row struct {
			ID          string  `json:"id"`
			Provider    string  `json:"provider"`
			Severity    string  `json:"severity"`
			Description string  `json:"description"`
			Verify      string  `json:"verify,omitempty"`
			Entropy     float64 `json:"entropy,omitempty"`
		}
		var rows []row
		for _, r := range set.Rules {
			rows = append(rows, row{r.ID, r.Provider, r.Severity, r.Description, r.Verify, r.Entropy})
		}
		_ = jsonEncoder(a.stdout).Encode(rows)
		return ExitClean
	}
	fmt.Fprintf(a.stdout, "%-32s %-18s %-8s %-12s %s\n", "ID", "PROVIDER", "SEV", "VERIFY", "DESCRIPTION")
	for _, r := range set.Rules {
		v := r.Verify
		if v == "" {
			v = "-"
		}
		fmt.Fprintf(a.stdout, "%-32s %-18s %-8s %-12s %s\n", r.ID, r.Provider, r.Severity, v, r.Description)
	}
	fmt.Fprintf(a.stdout, "\n%d rules.\n", len(set.Rules))
	return ExitClean
}
