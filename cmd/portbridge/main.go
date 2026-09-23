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

func main() {
	var cfgPath, tokenPath, logLevel string
	var showVersion, resetToken, cleanupNFT bool
	var validateBootstrap string
	var bootstrap stringList
	var prepareTLS, httpsInfo, httpsCheck, requireHTTPS bool
	var httpsOpts httpsOptions
	flag.StringVar(&cfgPath, "config", "/etc/portbridge/config.json", "configuration file path")
	flag.StringVar(&tokenPath, "token-file", "/etc/portbridge/admin.token", "file containing the generated admin token")
	flag.StringVar(&logLevel, "log-level", "info", "debug, info, warn, or error")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.BoolVar(&resetToken, "reset-admin-token", false, "generate a new admin token and exit")
	flag.BoolVar(&cleanupNFT, "cleanup-nft", false, "remove this application's owned nftables table and exit")
	flag.StringVar(&validateBootstrap, "validate-bootstrap-allow", "", "validate a comma-separated bootstrap IP/CIDR list and exit")
	flag.Var(&bootstrap, "bootstrap-allow", "temporary web ACL IP/CIDR; repeat or comma-separate")
	flag.BoolVar(&prepareTLS, "prepare-https", false, "prepare required HTTPS while the service is stopped")
	flag.BoolVar(&requireHTTPS, "require-https", false, "require HTTPS for the running management service")
	flag.BoolVar(&httpsInfo, "https-info", false, "inspect HTTPS certificate without changing configuration")
	flag.BoolVar(&httpsCheck, "check-https", false, "preflight existing or supplied TLS material without writes")
	flag.StringVar(&httpsOpts.dir, "https-dir", "/etc/portbridge-tls", "managed HTTPS directory")
	flag.StringVar(&httpsOpts.cert, "tls-cert", "", "certificate to import during HTTPS preparation")
	flag.StringVar(&httpsOpts.key, "tls-key", "", "private key to import during HTTPS preparation")
	flag.StringVar(&httpsOpts.language, "https-language", "en-US", "HTTPS setup message language")
	flag.IntVar(&httpsOpts.gid, "https-gid", -1, "read-only group for prepared certificate files")
	flag.Var(&httpsOpts.names, "tls-name", "additional DNS name or IP for a generated certificate")
	flag.Parse()
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
		items := strings.Split(validateBootstrap, ",")
		normalized, err := config.NormalizeWhitelist(items)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, raw := range normalized {
			if strings.HasSuffix(raw, "/0") {
				fmt.Fprintln(os.Stderr, "all-address /0 bootstrap ACL entries are not allowed")
				os.Exit(2)
			}
		}
		fmt.Println(strings.Join(normalized, ","))
		return
	}

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
	if cleanupNFT {
		nftConfig := config.Default().NFT
		if data, readErr := os.ReadFile(cfgPath); readErr == nil { // #nosec G304 -- the local root operator explicitly selects the cleanup configuration path.
			envelope := struct {
				NFT config.NFTConfig `json:"nftables"`
			}{NFT: nftConfig}
			if err := json.Unmarshal(data, &envelope); err != nil {
				logger.Error("cannot decode nftables cleanup configuration", "error", err)
				os.Exit(1)
			}
			nftConfig = envelope.NFT
			if nftConfig.ConntrackMark == 0 {
				nftConfig.ConntrackMark = config.DefaultNFTConntrackMark
			}
		} else if !os.IsNotExist(readErr) {
			logger.Error("cannot read nftables cleanup configuration", "error", readErr)
			os.Exit(1)
		}
		if err := proxy.CleanupNFTWithConfigPath(logger, cfgPath, nftConfig); err != nil {
			logger.Error("cannot clean up nftables data plane", "error", err)
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

	refreshStop := make(chan struct{})
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
			case <-refreshStop:
				return
			}
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	received := <-sig
	logger.Info("shutting down", "signal", fmt.Sprint(received))
	close(refreshStop)
	webServer.Close()
	proxyManager.Stop()
}

func rejectPositionalArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("unexpected positional argument %q; use -help to list supported options", args[0])
}
