package config

import (
	"io/ioutil"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
	"github.com/kelseyhightower/envconfig"
)

type ConfigPath struct {
	ConfigPath string `long:"config" env:"CONFIG" description:"yaml config file path"`
}

// Load loads config from ENV config or arguments config.
func Load(config interface{}) error {
	var c ConfigPath

	var ignoreUnknown flags.Options
	if s := os.Getenv("FLAGS_IGNORE_UNKNOWN"); strings.ToLower(s) == "true" || s == "1" {
		ignoreUnknown = flags.IgnoreUnknown
	}

	_, err := flags.NewParser(&c, flags.Default|ignoreUnknown).Parse()
	if err != nil {
		return err
	}
	if c.ConfigPath == "" {
		return envconfig.Process("", config)
	}

	return Read(c.ConfigPath, config)
}

// Read reads config from file.
func Read(filename string, config interface{}) error {
	cfg, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return Parse(cfg, config)
}
