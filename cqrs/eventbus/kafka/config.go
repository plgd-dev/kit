package kafka

import (
	"encoding/json"
	"fmt"
)

type Config struct {
	BootstrapServers []string `envconfig:"BOOTSTRAP_SERVERS" default:"localhost:9092"`
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}
