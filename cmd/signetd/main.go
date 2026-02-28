package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"signet/node"
)

func main() {
	configPath := flag.String("config", "./config.yaml", "path to YAML config file")
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
	flag.Parse()

	log, err := buildLogger(*logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	// Write a default config file if none exists.
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		defaults := &node.Config{
			KeyFile:    "./data/node.key",
			ListenAddr: "/ip4/0.0.0.0/tcp/9000",
			APIAddr:    ":8080",
			NodeType:   "public",
		}
		data, err := yaml.Marshal(defaults)
		if err != nil {
			log.Fatal("marshal default config", zap.Error(err))
		}
		if err := os.WriteFile(*configPath, data, 0644); err != nil {
			log.Fatal("write default config", zap.String("path", *configPath), zap.Error(err))
		}
		log.Info("wrote default config", zap.String("path", *configPath))
	}

	cfg, err := node.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("load config", zap.String("path", *configPath), zap.Error(err))
	}

	n, err := node.New(cfg, log)
	if err != nil {
		log.Fatal("create node", zap.Error(err))
	}

	if err := n.Start(); err != nil {
		log.Fatal("start node", zap.Error(err))
	}

	info := n.Info()
	log.Info("node ready",
		zap.String("peer_id", info.PeerID),
		zap.String("eth_addr", info.EthereumAddress),
		zap.Strings("addrs", info.Addrs),
		zap.String("api_addr", cfg.APIAddr),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()

	log.Info("signal received, shutting down")
	if err := n.Stop(); err != nil {
		log.Fatal("stop node", zap.Error(err))
	}
}

func buildLogger(levelStr string) (*zap.Logger, error) {
	atom, err := zap.ParseAtomicLevel(levelStr)
	if err != nil {
		return nil, fmt.Errorf("invalid log level %q: %w", levelStr, err)
	}
	cfg := zap.NewDevelopmentConfig()
	cfg.Level = atom
	cfg.DisableStacktrace = true
	return cfg.Build()
}
