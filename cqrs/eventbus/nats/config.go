package nats

import (
	"encoding/json"
	"fmt"

	nats "github.com/nats-io/go-nats"
)

type Config struct {
	URL     string `envconfig:"NATS_URL" default:"nats://localhost:4222"`
	Options []nats.Option
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}
