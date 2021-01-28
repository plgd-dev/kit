package queue

import (
	"runtime"
	"time"
)

// Config configuration for task queue.
type Config struct {
	// NumWorkers  number goroutine instances.
	NumWorkers int `yaml:"numWorkers" json:"numWorkers"`
	// Size size of queue. If it exhausted Submit returns error.
	Size int `yaml:"size" json:"size"`
	// MaxIdleTime sets up the interval time of cleaning up goroutines, 0 means never cleanup.
	MaxIdleTime time.Duration `yaml:"maxIdleTime" json:"maxIdleTime"`
	// PreAlloc indicates whether it should malloc for workers immediately.
	PreAlloc bool `yaml:"preAlloc" json:"preAlloc"`
}

// SetDefaults set zero values to defautls.
func (c *Config) SetDefaults() {
	if c.NumWorkers == 0 {
		c.NumWorkers = runtime.NumCPU() * 200
	}
	if c.Size == 0 {
		c.Size = 2 * 1024 * 1024
	}
}
