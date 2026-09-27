package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
	webui "portbridge/internal/web"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

var version = "dev"

type commandOptions struct {
	cfgPath, tokenPath, logLevel                    string
	showVersion, resetToken, cleanupNFT             bool
	validateBootstrap                               string
	bootstrap                                       stringList
	prepareTLS, httpsInfo, httpsCheck, requireHTTPS bool
	httpsOpts                                       httpsOptions
}

func parseOptions() commandOptions {
	var options commandOptions
	flag.StringVar(&options.cfgPath, "config", "/etc/portbridge/config.json", "configuration file path")
	flag.StringVar(&options.tokenPath, "token-file", "/etc/portbridge/admin.token", "file containing the generated admin token")
	flag.StringVar(&options.logLevel, "log-level", "info", "debug, info, warn, or error")
	flag.BoolVar(&options.showVersion, "version", false, "print version and exit")
	flag.BoolVar(&options.resetToken, "reset-admin-token", false, "generate a new admin token and exit")
	flag.BoolVar(&options.cleanupNFT, "cleanup-nft", false, "remove this application's owned nftables table and exit")
	flag.StringVar(&options.validateBootstrap, "validate-bootstrap-allow", "", "validate a comma-separated bootstrap IP/CIDR list and exit")
	flag.Var(&options.bootstrap, "bootstrap-allow", "temporary web ACL IP/CIDR; repeat or comma-separate")
	flag.BoolVar(&options.prepareTLS, "prepare-https", false, "prepare required HTTPS while the service is stopped")
	flag.BoolVar(&options.requireHTTPS, "require-https", false, "require HTTPS for the running management service")
	flag.BoolVar(&options.httpsInfo, "https-info", false, "inspect HTTPS certificate without changing configuration")
	flag.BoolVar(&options.httpsCheck, "check-https", false, "preflight existing or supplied TLS material without writes")
	flag.StringVar(&options.httpsOpts.dir, "https-dir", "/etc/portbridge-tls", "managed HTTPS directory")
	flag.StringVar(&options.httpsOpts.cert, "tls-cert", "", "certificate to import during HTTPS preparation")
	flag.StringVar(&options.httpsOpts.key, "tls-key", "", "private key to import during HTTPS preparation")
	flag.StringVar(&options.httpsOpts.language, "https-language", "en-US", "HTTPS setup message language")
	flag.IntVar(&options.httpsOpts.gid, "https-gid", -1, "read-only group for prepared certificate files")
	flag.Var(&options.httpsOpts.names, "tls-name", "additional DNS name or IP for a generated certificate")
	flag.Parse()
	return options
}

func main() {
	options := parseOptions()
	cfgPath, tokenPath, logLevel := options.cfgPath, options.tokenPath, options.logLevel
	showVersion, resetToken, cleanupNFT := options.showVersion, options.resetToken, options.cleanupNFT
	validateBootstrap, bootstrap := options.validateBootstrap, options.bootstrap
	prepareTLS, httpsInfo, httpsCheck, requireHTTPS, httpsOpts := options.prepareTLS, options.httpsInfo, options.httpsCheck, options.requireHTTPS, options.httpsOpts
	if err := rejectPositionalArgs(flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if showVersion {
		fmt.Println(version)
		return
	}
	if (httpsOpts.cert != "" || httpsOpts.key != "" || len(httpsOpts.names) > 0) && !prepareTLS && !httpsCheck {
		fmt.Fprintln(os.Stderr, "TLS import/name arguments require --prepare-https")
		os.Exit(2)
	}
	if httpsInfo {
		if err := readHTTPSInfo(cfgPath, httpsOpts.language); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if httpsCheck {
		if err := checkHTTPS(cfgPath, httpsOpts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if validateBootstrap != "" {
		if !printBootstrapWhitelist(validateBootstrap) {
			os.Exit(2)
		}
		return
	}

	logger := newLogger(logLevel)
	if cleanupNFT {
		if !runNFTCleanup(cfgPath, logger) {
			os.Exit(1)
		}
		return
	}

	store, generated, err := config.LoadOrCreate(cfgPath, tokenPath)
	if err != nil {
		logger.Error("cannot load configuration", "error", err)
		os.Exit(1)
	}
	if prepareTLS {
		if err := prepareHTTPS(store, httpsOpts); err != nil {
			logger.Error("cannot prepare required HTTPS", "error", err)
			os.Exit(1)
		}
		return
	}
	if generated != "" && !resetToken {
		logger.Info("generated initial admin token", "token_file", tokenPath)
	}
	if requireHTTPS {
		if _, err := store.Update(func(c *config.Config) error { c.Web.RequireHTTPS = true; return nil }); err != nil {
			logger.Error("HTTPS is required by the service", "error", err)
			os.Exit(1)
		}
	}
	if resetToken {
		token, err := store.RotateAdminToken(tokenPath)
		if err != nil {
			logger.Error("cannot reset admin token", "error", err)
			os.Exit(1)
		}
		fmt.Println(token)
		return
	}
	if generated == "" && !config.TokenFileConsistent(tokenPath, store.Get().Web.AdminTokenSHA) {
		logger.Error("admin token file does not hold the configured token (interrupted rotation or deleted file); stop the service and run 'portbridge --reset-admin-token' with the same config/token paths and file owner, then restart", "config_file", cfgPath, "token_file", tokenPath)
	}
	cfg := store.Get()
	aclManager, err := acl.New(cfg.Web.AutoLANACL, cfg.Web.StrictIPAllowlist, cfg.Web.Whitelist, bootstrap)
	if err != nil {
		logger.Error("cannot initialize web ACL", "error", err)
		os.Exit(1)
	}
	proxyManager := proxy.NewManager(logger, cfg.Web.DNSServers)
	if err := proxyManager.SetNFTStateConfigPath(cfgPath); err != nil {
		logger.Error("cannot select nft recovery location", "error", err)
		os.Exit(1)
	}
	proxyManager.SetRuntimeConfig(cfg.Limits, cfg.NFT)
	proxyManager.Apply(cfg.Rules)
	proxyManager.StartTelemetry()

	webServer, err := webui.New(store, aclManager, proxyManager, logger, tokenPath)
	if err != nil {
		logger.Error("cannot initialize web server", "error", err)
		os.Exit(1)
	}
	if err := webServer.Start(); err != nil {
		logger.Error("cannot start web server", "error", err)
		os.Exit(1)
	}

	refreshStop := startRefreshLoop(store, aclManager, proxyManager, bootstrap, logger)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	received := <-sig
	logger.Info("shutting down", "signal", fmt.Sprint(received))
	close(refreshStop)
	webServer.Close()
	proxyManager.Stop()
}

func printBootstrapWhitelist(raw string) bool {
	items := strings.Split(raw, ",")
	normalized, err := config.NormalizeWhitelist(items)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	for _, entry := range normalized {
		if strings.HasSuffix(entry, "/0") {
			fmt.Fprintln(os.Stderr, "all-address /0 bootstrap ACL entries are not allowed")
			return false
		}
	}
	fmt.Println(strings.Join(normalized, ","))
	return true
}

func newLogger(logLevel string) *slog.Logger {
	level := new(slog.LevelVar)
	switch strings.ToLower(logLevel) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "warn":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	return logger
}

func runNFTCleanup(cfgPath string, logger *slog.Logger) bool {
	nftConfig := config.Default().NFT
	if data, readErr := os.ReadFile(cfgPath); readErr == nil { // #nosec G304 -- the local root operator explicitly selects the cleanup configuration path.
		envelope := struct {
			NFT config.NFTConfig `json:"nftables"`
		}{NFT: nftConfig}
		if err := json.Unmarshal(data, &envelope); err != nil {
			logger.Error("cannot decode nftables cleanup configuration", "error", err)
			return false
		}
		nftConfig = envelope.NFT
		if nftConfig.ConntrackMark == 0 {
			nftConfig.ConntrackMark = config.DefaultNFTConntrackMark
		}
	} else if !os.IsNotExist(readErr) {
		logger.Error("cannot read nftables cleanup configuration", "error", readErr)
		return false
	}
	if err := proxy.CleanupNFTWithConfigPath(logger, cfgPath, nftConfig); err != nil {
		logger.Error("cannot clean up nftables data plane", "error", err)
		return false
	}
	return true
}

func startRefreshLoop(store *config.Store, aclManager *acl.Manager, proxyManager *proxy.Manager, bootstrap []string, logger *slog.Logger) chan struct{} {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				current := store.Get()
				if err := aclManager.Refresh(current.Web.AutoLANACL, current.Web.StrictIPAllowlist, current.Web.Whitelist, bootstrap); err != nil {
					logger.Warn("failed to refresh interface ACL", "error", err)
				}
				proxyManager.Refresh(current.Rules)
			case <-stop:
				return
			}
		}
	}()
	return stop
}

func rejectPositionalArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected positional argument %q; use -help to list supported options", args[0])
}
