package nats

import (
	"encoding/json"
	"fmt"

	nats "github.com/nats-io/nats.go"
)

type Config struct {
	URL     string `envconfig:"URL" default:"nats://localhost:4222"`
	Options []nats.Option
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}
