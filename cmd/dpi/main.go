package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"dpi-kyrsach/internal/config"
	"dpi-kyrsach/internal/dns"
	"dpi-kyrsach/internal/firewall"
	"dpi-kyrsach/internal/inspector"
	"dpi-kyrsach/internal/logger"
	"dpi-kyrsach/internal/runner"
)

func main() {
	configPath := flag.String("config", "configs/dpi.toml", "Path to TOML configuration file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	appLogger := logger.New(cfg.App.LogLevel)
	cmdRunner := runner.OSRunner{}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.DNS.Enabled {
		svc := dns.NewService(cmdRunner, cfg.DNS.ConfigPath, cfg.DNS.ReloadCommand)
		if err := svc.Apply(ctx, cfg.DNS.BlockedDomains); err != nil {
			appLogger.Error("dns setup failed", "error", err)
			os.Exit(1)
		}
		appLogger.Info("dns configured", "domains", len(cfg.DNS.BlockedDomains))
	} else {
		appLogger.Info("dns module disabled")
	}

	if cfg.Firewall.Enabled {
		fw := firewall.NewManager(cmdRunner, cfg.Firewall.Family, cfg.Firewall.Table, cfg.Firewall.Chain, cfg.Firewall.SetName)
		if err := fw.Ensure(ctx); err != nil {
			appLogger.Error("firewall bootstrap failed", "error", err)
			os.Exit(1)
		}
		if cfg.Inspector.Enabled {
			if err := fw.EnsureQueueRule(ctx, cfg.Inspector.QueueNum); err != nil {
				appLogger.Error("firewall nfqueue rule bootstrap failed", "error", err)
				os.Exit(1)
			}
		}
		if err := fw.AddBlockedIPs(ctx, cfg.Firewall.BlockedIPs); err != nil {
			appLogger.Error("firewall blocked IP bootstrap failed", "error", err)
			os.Exit(1)
		}
		appLogger.Info("firewall configured", "blocked_ips", len(cfg.Firewall.BlockedIPs))
	} else {
		appLogger.Info("firewall module disabled")
		if cfg.Inspector.Enabled {
			appLogger.Warn("inspector is enabled but firewall is disabled; nfqueue rule will not be installed")
		}
	}

	var wg sync.WaitGroup
	if cfg.Inspector.Enabled {
		ins := inspector.New(inspector.Config{
			Enabled:        cfg.Inspector.Enabled,
			QueueNum:       cfg.Inspector.QueueNum,
			FailOpen:       cfg.Inspector.FailOpen,
			Mode:           cfg.Inspector.Mode,
			BlockedDomains: cfg.DNS.BlockedDomains,
		}, appLogger.With("component", "inspector"))

		wg.Go(func() {
			if runErr := ins.Run(ctx); runErr != nil {
				appLogger.Error("inspector stopped with error", "error", runErr)
			}
		})
	} else {
		appLogger.Info("inspector module disabled")
	}

	appLogger.Info("dpi prototype started", "config", *configPath)
	<-ctx.Done()
	appLogger.Info("shutdown requested")
	wg.Wait()
	appLogger.Info("stopped")
}
