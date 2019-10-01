package mongodb

import (
	"encoding/json"
	"fmt"
	"time"
)

type Config struct {
	URI             string        `envconfig:"URI" default:"mongodb://localhost:27017"`
	DatabaseName    string        `envconfig:"DATABASE" default:"eventStore"`
	BatchSize       int           `envconfig:"BATCH_SIZE" default:"16"`
	MaxPoolSize     uint64        `envconfig:"MAX_POOL_SIZE" default:"16"`
	MaxConnIdleTime time.Duration `envconfig:"MAX_CONN_IDLE_TIME" default:"240s"`
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}
