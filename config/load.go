package config

import (
	"io/ioutil"

	"github.com/jessevdk/go-flags"
	"github.com/kelseyhightower/envconfig"
)

type ConfigPath struct {
	ConfigPath string `long:"config" description:"yaml config file path"`
}

// Load loads config from ENV config or arguments config.
func Load(config interface{}) error {
	var c ConfigPath
	_, err := flags.NewParser(&c, flags.Default|flags.IgnoreUnknown).Parse()
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
