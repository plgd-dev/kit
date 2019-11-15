package mongodb

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-ocf/cqrs/event"
)

type Option func(Config) Config

func WithUnmmarshaler(f event.UnmarshalerFunc) Option {
	return func(cfg Config) Config {
		cfg.unmarshalerFunc = f
		return cfg
	}
}

// Config provides Mongo DB configuration options
type Config struct {
	URI             string        `long:"uri" envconfig:"URI" default:"mongodb://localhost:27017"`
	DatabaseName    string        `long:"dbName" envconfig:"DATABASE" default:"eventStore"`
	BatchSize       int           `long:"batchSize" envconfig:"BATCH_SIZE" default:"16"`
	MaxPoolSize     uint64        `long:"maxPoolSize" envconfig:"MAX_POOL_SIZE" default:"16"`
	MaxConnIdleTime time.Duration `long:"maxConnIdleTime" envconfig:"MAX_CONN_IDLE_TIME" default:"240s"`
	unmarshalerFunc event.UnmarshalerFunc
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}
