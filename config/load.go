package config

import (
	"io/ioutil"

	"github.com/jessevdk/go-flags"
	"github.com/kelseyhightower/envconfig"
)

type ConfigPath struct {
	FromYAML   bool   `long:"fromYaml" env:"FROM_YAML" description:"load configuration from yaml file otherwise from ENV"`
	ConfigPath string `long:"config" env:"CONFIG" default:"config.yaml" description:"yaml config file path"`
}

// Load loads config from ENV config or arguments config.
func Load(config interface{}) error {
	var c ConfigPath
	_, err := flags.Parse(&c)
	if err != nil {
		return err
	}
	if !c.FromYAML {
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
