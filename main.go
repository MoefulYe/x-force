package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	_ "github.com/xjasonlyu/tun2socks/v2/dns"
	t2sengine "github.com/xjasonlyu/tun2socks/v2/engine"
	t2slog "github.com/xjasonlyu/tun2socks/v2/log"
)

const (
	version             = "0.1.0"
	defaultTunDevice    = "tun0"
	defaultUplinkDevice = "tap0"
	defaultTunCIDR      = "198.18.0.1/15"
	ifaceRetries        = 200
)

var requiredDependencies = []string{
	"slirp4netns",
}

type usageError struct {
	msg string
}

func (e usageError) Error() string {
	return e.msg
}

type config struct {
	proxyURL   string
	tunDevice  string
	tunCIDR    string
	uplinkDev  string
	tunLogPath string
	slirpLog   string
	showHelp   bool
	showVer    bool
	command    []string
}

type workerConfig struct {
	proxyURL   string
	proxyIPv4  string
	tunDevice  string
	tunCIDR    string
	uplinkDev  string
	tunLogPath string
	command    []string
}

type routeSpec struct {
	linkIndex int
	via       net.IP
}

type runtimeState struct {
	tunLogPath string
	slirpLog   string

	workerCmd *exec.Cmd
	slirpCmd  *exec.Cmd
}

func usage(w io.Writer) {
	script := filepath.Base(os.Args[0])
	fmt.Fprintf(w, "xforce %s\n\n", version)
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s [-x <proxy_url>] [-d <tun_dev>] [--tun-cidr <cidr>] [-u <uplink_dev>] [-l <tun2socks_log>] [--slirp-log <file>] [--] <command> [args...]\n", script)
	fmt.Fprintf(w, "  %s --help\n", script)
	fmt.Fprintf(w, "  %s --version\n\n", script)
	fmt.Fprintf(w, "Description:\n")
	fmt.Fprintf(w, "  Run a command in an isolated rootless netns and force its traffic through tun2socks.\n\n")
	fmt.Fprintf(w, "Options:\n")
	fmt.Fprintf(w, "  -x, --proxy <proxy_url>     Upstream proxy URL.\n")
	fmt.Fprintf(w, "  -d, --device <tun_dev>      TUN device name. Default: %s\n", defaultTunDevice)
	fmt.Fprintf(w, "      --tun-cidr <cidr>       TUN IPv4 CIDR address. Default: %s\n", defaultTunCIDR)
	fmt.Fprintf(w, "  -u, --uplink-dev <tap_dev>  slirp4netns uplink name. Default: %s\n", defaultUplinkDevice)
	fmt.Fprintf(w, "  -l, --log-file <path>       tun2socks log path (default: silent).\n")
	fmt.Fprintf(w, "      --slirp-log <path>      slirp4netns log path (default: silent).\n")
	fmt.Fprintf(w, "  -h, --help                  Show help.\n")
	fmt.Fprintf(w, "  -v, --version               Show version.\n\n")
	fmt.Fprintf(w, "Environment fallback for proxy:\n")
	fmt.Fprintf(w, "  ALL_PROXY -> all_proxy -> http_proxy -> HTTP_PROXY -> https_proxy -> HTTPS_PROXY\n")
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	exitCode := run(ctx, os.Args[1:])
	os.Exit(exitCode)
}

func run(ctx context.Context, args []string) int {
	if len(args) > 0 && args[0] == "--worker" {
		return runWorker(ctx, args[1:])
	}

	cfg, err := parseArgs(args)
	if err != nil {
		var uerr usageError
		if errors.As(err, &uerr) {
			fmt.Fprintf(os.Stderr, "Error: %s\n\n", uerr.msg)
			usage(os.Stderr)
			return 2
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if cfg.showHelp {
		usage(os.Stdout)
		return 0
	}
	if cfg.showVer {
		fmt.Println(version)
		return 0
	}

	if runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "Error: xforce requires Linux namespaces; current GOOS=%s\n", runtime.GOOS)
		return 1
	}
	if err := checkDependencies(requiredDependencies); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	proxyURL := cfg.proxyURL
	if proxyURL == "" {
		proxyURL = proxyFromEnv()
	}
	if proxyURL == "" {
		fmt.Fprintln(os.Stderr, "Error: proxy is empty; use -x/--proxy or set ALL_PROXY")
		return 2
	}

	proxyHost, err := parseProxyHost(proxyURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid proxy URL %q: %v\n", proxyURL, err)
		return 1
	}
	proxyIPv4, err := resolveIPv4(ctx, proxyHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot resolve proxy host %q: %v\n", proxyHost, err)
		return 1
	}

	state, err := prepareRuntime(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	defer state.cleanup()

	if err := state.startWorker(ctx, cfg, proxyURL, proxyIPv4); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if err := state.startSlirp(ctx, cfg.uplinkDev); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		printTail(os.Stderr, state.slirpLog, 50)
		return 1
	}

	if err := state.waitWorker(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Error: worker failed: %v\n", err)
		printTail(os.Stderr, state.tunLogPath, 50)
		printTail(os.Stderr, state.slirpLog, 50)
		return 1
	}

	return 0
}

func runWorker(ctx context.Context, args []string) int {
	if runtime.GOOS != "linux" {
		fmt.Fprintf(os.Stderr, "Error: worker requires Linux; current GOOS=%s\n", runtime.GOOS)
		return 1
	}

	cfg, err := parseWorkerArgs(args)
	if err != nil {
		var uerr usageError
		if errors.As(err, &uerr) {
			fmt.Fprintf(os.Stderr, "Error: %s\n", uerr.msg)
			return 2
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if err := runWorkerMain(ctx, cfg); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		tunDevice: defaultTunDevice,
		uplinkDev: defaultUplinkDevice,
		tunCIDR:   defaultTunCIDR,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if arg == "--" {
			cfg.command = append([]string{}, args[i+1:]...)
			break
		}

		switch {
		case arg == "-h" || arg == "--help":
			cfg.showHelp = true
		case arg == "-v" || arg == "--version":
			cfg.showVer = true
		case arg == "-x" || arg == "--proxy":
			if i+1 >= len(args) {
				return cfg, usageError{msg: fmt.Sprintf("option %s requires a value", arg)}
			}
			i++
			cfg.proxyURL = args[i]
		case strings.HasPrefix(arg, "--proxy="):
			cfg.proxyURL = strings.TrimPrefix(arg, "--proxy=")
		case arg == "-d" || arg == "--device":
			if i+1 >= len(args) {
				return cfg, usageError{msg: fmt.Sprintf("option %s requires a value", arg)}
			}
			i++
			cfg.tunDevice = args[i]
		case strings.HasPrefix(arg, "--device="):
			cfg.tunDevice = strings.TrimPrefix(arg, "--device=")
		case arg == "--tun-cidr":
			if i+1 >= len(args) {
				return cfg, usageError{msg: fmt.Sprintf("option %s requires a value", arg)}
			}
			i++
			cfg.tunCIDR = args[i]
		case strings.HasPrefix(arg, "--tun-cidr="):
			cfg.tunCIDR = strings.TrimPrefix(arg, "--tun-cidr=")
		case arg == "-u" || arg == "--uplink-dev":
			if i+1 >= len(args) {
				return cfg, usageError{msg: fmt.Sprintf("option %s requires a value", arg)}
			}
			i++
			cfg.uplinkDev = args[i]
		case strings.HasPrefix(arg, "--uplink-dev="):
			cfg.uplinkDev = strings.TrimPrefix(arg, "--uplink-dev=")
		case arg == "-l" || arg == "--log-file":
			if i+1 >= len(args) {
				return cfg, usageError{msg: fmt.Sprintf("option %s requires a value", arg)}
			}
			i++
			cfg.tunLogPath = args[i]
		case strings.HasPrefix(arg, "--log-file="):
			cfg.tunLogPath = strings.TrimPrefix(arg, "--log-file=")
		case arg == "--slirp-log":
			if i+1 >= len(args) {
				return cfg, usageError{msg: fmt.Sprintf("option %s requires a value", arg)}
			}
			i++
			cfg.slirpLog = args[i]
		case strings.HasPrefix(arg, "--slirp-log="):
			cfg.slirpLog = strings.TrimPrefix(arg, "--slirp-log=")
		case strings.HasPrefix(arg, "-"):
			return cfg, usageError{msg: fmt.Sprintf("unknown option: %s", arg)}
		default:
			cfg.command = append([]string{}, args[i:]...)
			i = len(args)
		}
	}

	if !cfg.showHelp && !cfg.showVer && len(cfg.command) == 0 {
		return cfg, usageError{msg: "missing target command; use '<command> [args...]'"}
	}
	if !cfg.showHelp && !cfg.showVer {
		if err := validateTunCIDR(cfg.tunCIDR); err != nil {
			return cfg, usageError{msg: fmt.Sprintf("invalid --tun-cidr %q: %v", cfg.tunCIDR, err)}
		}
	}

	return cfg, nil
}

func parseWorkerArgs(args []string) (workerConfig, error) {
	cfg := workerConfig{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			cfg.command = append([]string{}, args[i+1:]...)
			break
		}

		switch {
		case arg == "--proxy":
			if i+1 >= len(args) {
				return cfg, usageError{msg: "option --proxy requires a value"}
			}
			i++
			cfg.proxyURL = args[i]
		case strings.HasPrefix(arg, "--proxy="):
			cfg.proxyURL = strings.TrimPrefix(arg, "--proxy=")
		case arg == "--proxy-ipv4":
			if i+1 >= len(args) {
				return cfg, usageError{msg: "option --proxy-ipv4 requires a value"}
			}
			i++
			cfg.proxyIPv4 = args[i]
		case strings.HasPrefix(arg, "--proxy-ipv4="):
			cfg.proxyIPv4 = strings.TrimPrefix(arg, "--proxy-ipv4=")
		case arg == "--device":
			if i+1 >= len(args) {
				return cfg, usageError{msg: "option --device requires a value"}
			}
			i++
			cfg.tunDevice = args[i]
		case strings.HasPrefix(arg, "--device="):
			cfg.tunDevice = strings.TrimPrefix(arg, "--device=")
		case arg == "--tun-cidr":
			if i+1 >= len(args) {
				return cfg, usageError{msg: "option --tun-cidr requires a value"}
			}
			i++
			cfg.tunCIDR = args[i]
		case strings.HasPrefix(arg, "--tun-cidr="):
			cfg.tunCIDR = strings.TrimPrefix(arg, "--tun-cidr=")
		case arg == "--uplink-dev":
			if i+1 >= len(args) {
				return cfg, usageError{msg: "option --uplink-dev requires a value"}
			}
			i++
			cfg.uplinkDev = args[i]
		case strings.HasPrefix(arg, "--uplink-dev="):
			cfg.uplinkDev = strings.TrimPrefix(arg, "--uplink-dev=")
		case arg == "--tun-log":
			if i+1 >= len(args) {
				return cfg, usageError{msg: "option --tun-log requires a value"}
			}
			i++
			cfg.tunLogPath = args[i]
		case strings.HasPrefix(arg, "--tun-log="):
			cfg.tunLogPath = strings.TrimPrefix(arg, "--tun-log=")
		case strings.HasPrefix(arg, "-"):
			return cfg, usageError{msg: fmt.Sprintf("unknown worker option: %s", arg)}
		default:
			return cfg, usageError{msg: fmt.Sprintf("unexpected worker argument: %s", arg)}
		}
	}

	if cfg.proxyURL == "" {
		return cfg, usageError{msg: "worker requires --proxy"}
	}
	if cfg.proxyIPv4 == "" {
		return cfg, usageError{msg: "worker requires --proxy-ipv4"}
	}
	if ip := net.ParseIP(cfg.proxyIPv4); ip == nil || ip.To4() == nil {
		return cfg, usageError{msg: fmt.Sprintf("worker --proxy-ipv4 must be IPv4, got %q", cfg.proxyIPv4)}
	}
	if cfg.tunDevice == "" {
		return cfg, usageError{msg: "worker requires --device"}
	}
	if cfg.tunCIDR == "" {
		return cfg, usageError{msg: "worker requires --tun-cidr"}
	}
	if err := validateTunCIDR(cfg.tunCIDR); err != nil {
		return cfg, usageError{msg: fmt.Sprintf("invalid --tun-cidr %q: %v", cfg.tunCIDR, err)}
	}
	if cfg.uplinkDev == "" {
		return cfg, usageError{msg: "worker requires --uplink-dev"}
	}
	if len(cfg.command) == 0 {
		return cfg, usageError{msg: "worker requires target command after '--'"}
	}

	return cfg, nil
}

func validateTunCIDR(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return fmt.Errorf("empty value")
	}

	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	if ip.To4() == nil {
		return fmt.Errorf("IPv4 CIDR required")
	}
	return nil
}

func proxyFromEnv() string {
	keys := []string{"ALL_PROXY", "all_proxy", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"}
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func checkDependencies(deps []string) error {
	var missing []string
	for _, dep := range deps {
		if _, err := exec.LookPath(dep); err != nil {
			missing = append(missing, dep)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

func parseProxyHost(proxyURL string) (string, error) {
	raw := strings.TrimSpace(proxyURL)
	if raw == "" {
		return "", fmt.Errorf("empty proxy")
	}

	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		host := u.Hostname()
		if host == "" {
			return "", fmt.Errorf("proxy host is empty")
		}
		return host, nil
	}

	if strings.Count(raw, ":") == 1 {
		if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
			return host, nil
		}
	}
	return raw, nil
}

func resolveIPv4(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String(), nil
		}
		return "", fmt.Errorf("proxy host %q resolves to non-IPv4 address", host)
	}

	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip4", host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IPv4 address found")
	}
	return ips[0].String(), nil
}

func prepareRuntime(cfg config) (*runtimeState, error) {
	state := &runtimeState{
		tunLogPath: strings.TrimSpace(cfg.tunLogPath),
		slirpLog:   strings.TrimSpace(cfg.slirpLog),
	}

	return state, nil
}

func (s *runtimeState) cleanup() {
	stopProcess(s.workerCmd)
	stopProcess(s.slirpCmd)
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(1 * time.Second):
	}

	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}
}

func (s *runtimeState) startWorker(ctx context.Context, cfg config, proxyURL, proxyIPv4 string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	args := []string{
		"--worker",
		"--proxy", proxyURL,
		"--proxy-ipv4", proxyIPv4,
		"--device", cfg.tunDevice,
		"--tun-cidr", cfg.tunCIDR,
		"--uplink-dev", cfg.uplinkDev,
		"--tun-log", s.tunLogPath,
		"--",
	}
	args = append(args, cfg.command...)

	cmd := exec.CommandContext(ctx, exePath, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappingsEnableSetgroups: false,
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	s.workerCmd = cmd
	return nil
}

func (s *runtimeState) waitWorker() error {
	if s.workerCmd == nil {
		return fmt.Errorf("worker is not started")
	}
	return s.workerCmd.Wait()
}

func (s *runtimeState) startSlirp(ctx context.Context, uplinkDev string) error {
	if s.workerCmd == nil || s.workerCmd.Process == nil {
		return fmt.Errorf("start slirp4netns: worker is not started")
	}

	cmd, err := startLoggedProcess(
		ctx,
		s.slirpLog,
		"slirp4netns",
		"--configure",
		"--mtu=1500",
		"--disable-host-loopback",
		fmt.Sprintf("%d", s.workerCmd.Process.Pid),
		uplinkDev,
	)
	if err != nil {
		return fmt.Errorf("start slirp4netns: %w", err)
	}
	s.slirpCmd = cmd
	return nil
}

func runWorkerMain(ctx context.Context, cfg workerConfig) error {
	var logger *zap.Logger
	if strings.TrimSpace(cfg.tunLogPath) != "" {
		var err error
		logger, err = newTun2socksLogger(cfg.tunLogPath)
		if err != nil {
			return err
		}
		defer logger.Sync()
	}

	if err := waitForLink(ctx, cfg.uplinkDev, ifaceRetries); err != nil {
		return fmt.Errorf("uplink device not ready (%s): %w", cfg.uplinkDev, err)
	}

	route, err := routeToProxy(cfg.proxyIPv4)
	if err != nil {
		return fmt.Errorf("cannot resolve route to proxy %s: %w", cfg.proxyIPv4, err)
	}

	t2sengine.Insert(&t2sengine.Key{
		Device:    "tun://" + cfg.tunDevice,
		Proxy:     cfg.proxyURL,
		Interface: cfg.uplinkDev,
		LogLevel:  "silent",
	})
	t2sengine.Start()
	defer t2sengine.Stop()
	if logger != nil {
		t2slog.SetLogger(logger)
	}

	if err := waitForLink(ctx, cfg.tunDevice, ifaceRetries); err != nil {
		return fmt.Errorf("tun device not ready (%s): %w", cfg.tunDevice, err)
	}

	if err := configureRoutes(cfg.tunDevice, cfg.tunCIDR, cfg.proxyIPv4, route); err != nil {
		return fmt.Errorf("configure routes failed: %w", err)
	}

	return runTarget(ctx, cfg.command)
}

func newTun2socksLogger(logPath string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.OutputPaths = []string{logPath}
	cfg.ErrorOutputPaths = []string{logPath}
	logger, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("create tun2socks logger: %w", err)
	}
	return logger, nil
}

func waitForLink(ctx context.Context, iface string, retries int) error {
	for i := 0; i < retries; i++ {
		if _, err := netlink.LinkByName(iface); err == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("interface %s not found", iface)
}

func routeToProxy(ipAddr string) (routeSpec, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil || ip.To4() == nil {
		return routeSpec{}, fmt.Errorf("invalid IPv4 address %q", ipAddr)
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return routeSpec{}, err
	}
	if len(routes) == 0 {
		return routeSpec{}, fmt.Errorf("no route found")
	}

	r := routes[0]
	if r.LinkIndex <= 0 {
		return routeSpec{}, fmt.Errorf("invalid route link index: %d", r.LinkIndex)
	}
	return routeSpec{linkIndex: r.LinkIndex, via: r.Gw}, nil
}

func configureRoutes(tunDev, tunCIDR, proxyIPv4 string, route routeSpec) error {
	tunLink, err := netlink.LinkByName(tunDev)
	if err != nil {
		return err
	}

	_, tunNet, err := net.ParseCIDR(tunCIDR)
	if err != nil {
		return err
	}

	if err := netlink.AddrReplace(tunLink, &netlink.Addr{IPNet: tunNet}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(tunLink); err != nil {
		return err
	}

	_, dst, err := net.ParseCIDR(proxyIPv4 + "/32")
	if err != nil {
		return err
	}
	proxyRoute := &netlink.Route{
		Dst:       dst,
		LinkIndex: route.linkIndex,
	}
	if route.via != nil && route.via.To4() != nil {
		proxyRoute.Gw = route.via
	}
	if err := netlink.RouteReplace(proxyRoute); err != nil {
		return err
	}

	defaultRoute := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		},
		LinkIndex: tunLink.Attrs().Index,
	}
	if err := netlink.RouteReplace(defaultRoute); err != nil {
		return err
	}

	return nil
}

func runTarget(ctx context.Context, command []string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func startLoggedProcess(ctx context.Context, logPath string, args ...string) (*exec.Cmd, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	if strings.TrimSpace(logPath) == "" {
		logPath = os.DevNull
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", logPath, err)
	}
	defer logFile.Close()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

func parseRouteLine(line string) (dev, via string) {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			dev = fields[i+1]
		}
		if fields[i] == "via" {
			via = fields[i+1]
		}
	}
	return dev, via
}

func printTail(w io.Writer, path string, lines int) {
	if path == "" || path == os.DevNull {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	all := strings.Split(string(data), "\n")
	start := 0
	if len(all) > lines {
		start = len(all) - lines
	}
	fmt.Fprintf(w, "Last %d lines from %s:\n", lines, path)
	for _, ln := range all[start:] {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		fmt.Fprintln(w, ln)
	}
}
