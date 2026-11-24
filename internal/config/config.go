// Copyright 2026 Binerals Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config reads the agent's settings. A flag wins over the environment, which wins over the
// config file (/etc/flawrook/agent.yaml by default). Nothing here is hard-coded but the default URL.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	DefaultURL  = "https://flawrook.dev"
	DefaultPath = "/etc/flawrook/agent.yaml"

	// Cluster mode's defaults (the cluster contract's configuration names); server mode ignores these settings.
	DefaultClusterInterval   = time.Hour
	DefaultSBOMMaxImageBytes = 300 << 20 // compressed layers; a larger image is reported too-large, not pulled
	DefaultSBOMConcurrency   = 1
)

// Config is what one run of the agent uses.
type Config struct {
	URL           string // without a trailing slash
	Token         string
	Hostname      string // overrides the real hostname when set
	CAFile        string // a PEM bundle trusted besides the system's
	HTTPSProxy    string
	NoProxy       string
	IncludeMounts []string // network or FUSE mount points walked all the same (absolute, cleaned)
	// ReadProtected says the unit was given CAP_DAC_READ_SEARCH (install.sh's FLAWROOK_READ_PROTECTED=1 drop-in),
	// to read files no other user may; off, the agent reads what's world-readable, as the catalogers need.
	ReadProtected bool

	// Cluster mode (the Helm chart sets FLAWROOK_MODE=cluster). A zero value is the default; server mode ignores
	// all of these, and cluster mode ignores Hostname, IncludeMounts and ReadProtected.
	Mode              string        // "" or "server", or "cluster"
	ClusterName       string        // shown instead of the cluster id; the chart's clusterName
	Interval          time.Duration // between runs; 0 is DefaultClusterInterval
	NamespacesInclude []string      // exact names; none means every namespace
	NamespacesExclude []string
	SBOMMaxImageBytes int64 // 0 is DefaultSBOMMaxImageBytes
	SBOMConcurrency   int   // 0 is DefaultSBOMConcurrency
}

// Cluster says the agent runs in cluster mode.
func (c Config) Cluster() bool { return c.Mode == "cluster" }

// RunInterval is cluster mode's time between runs.
func (c Config) RunInterval() time.Duration {
	if c.Interval == 0 {
		return DefaultClusterInterval
	}
	return c.Interval
}

// MaxImageBytes is the largest image, by its compressed layers, that cluster mode pulls.
func (c Config) MaxImageBytes() int64 {
	if c.SBOMMaxImageBytes == 0 {
		return DefaultSBOMMaxImageBytes
	}
	return c.SBOMMaxImageBytes
}

// Concurrency is how many images cluster mode builds at once.
func (c Config) Concurrency() int {
	if c.SBOMConcurrency == 0 {
		return DefaultSBOMConcurrency
	}
	return c.SBOMConcurrency
}

// Equal tells a SIGHUP whether the config changed.
func (c Config) Equal(o Config) bool { return reflect.DeepEqual(c, o) }

// The config file's keys, which are also the keys of Sources.Flags.
type file struct {
	URL        string `yaml:"url"`
	Token      string `yaml:"token"`
	Hostname   string `yaml:"hostname"`
	CAFile     string `yaml:"ca_file"`
	HTTPSProxy string `yaml:"https_proxy"`
	NoProxy    string `yaml:"no_proxy"`
	// A list in the file; comma-separated as a flag or in the environment.
	IncludeMounts []string `yaml:"include_mounts"`
	ReadProtected bool     `yaml:"read_protected"`
	// Cluster mode.
	Mode              string   `yaml:"mode"`
	ClusterName       string   `yaml:"cluster_name"`
	Interval          string   `yaml:"interval"` // a Go duration, 10m to 24h
	NamespacesInclude []string `yaml:"namespaces_include"`
	NamespacesExclude []string `yaml:"namespaces_exclude"`
	SBOMMaxImageBytes int64    `yaml:"sbom_max_image_bytes"`
	SBOMConcurrency   int      `yaml:"sbom_concurrency"`
}

// The environment variables per key, the first set one wins.
var envNames = map[string][]string{
	"url":         {"FLAWROOK_URL"},
	"token":       {"FLAWROOK_TOKEN"},
	"hostname":    {"FLAWROOK_HOSTNAME"},
	"ca_file":     {"FLAWROOK_CA_FILE"},
	"https_proxy": {"HTTPS_PROXY", "https_proxy"},
	"no_proxy":    {"NO_PROXY", "no_proxy"},
	// true or false, as strconv.ParseBool reads it (1, t, TRUE, ...).
	"read_protected": {"FLAWROOK_READ_PROTECTED"},
	// Cluster mode; the namespace lists are comma-separated.
	"mode":                 {"FLAWROOK_MODE"},
	"cluster_name":         {"FLAWROOK_CLUSTER_NAME"},
	"interval":             {"FLAWROOK_INTERVAL"},
	"namespaces_include":   {"FLAWROOK_NAMESPACES_INCLUDE"},
	"namespaces_exclude":   {"FLAWROOK_NAMESPACES_EXCLUDE"},
	"sbom_max_image_bytes": {"FLAWROOK_SBOM_MAX_IMAGE_BYTES"},
	"sbom_concurrency":     {"FLAWROOK_SBOM_CONCURRENCY"},
}

// Sources are where the settings come from: the flags given on the command line (by key; a flag
// that wasn't given is absent), the environment, and the config file's path.
type Sources struct {
	Flags map[string]string
	Env   func(string) string
	Path  string
}

// Load reads the settings in their order of precedence. A missing config file is fine (the
// environment can carry everything); an unreadable or invalid one is an error.
func Load(s Sources) (Config, error) {
	f, err := readFile(s.Path)
	if err != nil {
		return Config{}, err
	}
	pick := func(key, fromFile string) string {
		if v, ok := s.Flags[key]; ok {
			return v
		}
		for _, name := range envNames[key] {
			if v := s.Env(name); v != "" {
				return v
			}
		}
		return fromFile
	}
	c := Config{
		URL:        pick("url", f.URL),
		Token:      pick("token", f.Token),
		Hostname:   pick("hostname", f.Hostname),
		CAFile:     pick("ca_file", f.CAFile),
		HTTPSProxy: pick("https_proxy", f.HTTPSProxy),
		NoProxy:    pick("no_proxy", f.NoProxy),
	}
	c.ReadProtected = f.ReadProtected
	if v := pick("read_protected", ""); v != "" {
		on, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("read_protected: %q is neither true nor false", v)
		}
		c.ReadProtected = on
	}
	include := f.IncludeMounts
	if v, ok := s.Flags["include_mounts"]; ok {
		include = strings.Split(v, ",")
	} else if v := s.Env("FLAWROOK_INCLUDE_MOUNTS"); v != "" {
		include = strings.Split(v, ",")
	}
	for _, p := range include {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			return Config{}, fmt.Errorf("include_mounts: %q is not an absolute path", p)
		}
		c.IncludeMounts = append(c.IncludeMounts, filepath.Clean(p))
	}
	if err := loadCluster(&c, f, pick, s.Flags); err != nil {
		return Config{}, err
	}
	if c.URL == "" {
		c.URL = DefaultURL
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if err := checkURL(c.URL); err != nil {
		return Config{}, err
	}
	return c, nil
}

// loadCluster reads cluster mode's settings, in the same order of precedence, and checks them.
func loadCluster(c *Config, f file, pick func(key, fromFile string) string, flags map[string]string) error {
	c.Mode = pick("mode", f.Mode)
	switch c.Mode {
	case "", "server", "cluster":
	default:
		return fmt.Errorf("mode: %q is neither server nor cluster", c.Mode)
	}
	c.ClusterName = strings.TrimSpace(pick("cluster_name", f.ClusterName))
	if v := pick("interval", f.Interval); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 10*time.Minute || d > 24*time.Hour {
			return fmt.Errorf("interval: %q is not a duration from 10m to 24h", v)
		}
		c.Interval = d
	}
	list := func(key string, fromFile []string) []string {
		items := fromFile
		if v := pick(key, ""); v != "" {
			items = strings.Split(v, ",")
		} else if _, ok := flags[key]; ok {
			items = nil // given empty
		}
		var out []string
		for _, n := range items {
			if n = strings.TrimSpace(n); n != "" {
				out = append(out, n)
			}
		}
		return out
	}
	c.NamespacesInclude = list("namespaces_include", f.NamespacesInclude)
	c.NamespacesExclude = list("namespaces_exclude", f.NamespacesExclude)
	c.SBOMMaxImageBytes = f.SBOMMaxImageBytes
	if v := pick("sbom_max_image_bytes", ""); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("sbom_max_image_bytes: %q is not a whole number of bytes", v)
		}
		c.SBOMMaxImageBytes = n
	}
	if c.SBOMMaxImageBytes < 0 {
		return fmt.Errorf("sbom_max_image_bytes: %d is negative", c.SBOMMaxImageBytes)
	}
	c.SBOMConcurrency = f.SBOMConcurrency
	if v := pick("sbom_concurrency", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("sbom_concurrency: %q is not a number from 1 to 4", v)
		}
		c.SBOMConcurrency = n
	}
	if c.SBOMConcurrency != 0 && (c.SBOMConcurrency < 1 || c.SBOMConcurrency > 4) {
		return fmt.Errorf("sbom_concurrency: %d is not from 1 to 4", c.SBOMConcurrency)
	}
	return nil
}

func readFile(path string) (file, error) {
	var f file
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if errors.Is(err, fs.ErrPermission) {
		return f, fmt.Errorf("config %s: %w. The service reads it as a member of the flawrook group: agent.yaml needs mode 0640 root:flawrook and /etc/flawrook 0750 root:flawrook, as install.sh sets them", path, err)
	}
	if err != nil {
		return f, fmt.Errorf("config %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // a misspelt key is an error, not a silently ignored setting
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return f, fmt.Errorf("config %s: %w", path, err)
	}
	return f, nil
}

// checkURL allows HTTPS, and plain HTTP only to this machine: the token never crosses a network in clear.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("url %q: not an absolute URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("url %q: plain http is allowed only to localhost; use https", raw)
	default:
		return fmt.Errorf("url %q: the scheme must be https", raw)
	}
}
