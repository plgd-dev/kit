package queue

import (
	"runtime"
	"time"
)

// Config configuration for task queue.
type Config struct {
	// GoroutinePoolSize maximum number of running goroutine instances.
	GoroutinePoolSize int `yaml:"goroutinePoolSize" json:"goroutinePoolSize"`
	// Size size of queue. If it exhausted Submit returns error.
	Size int `yaml:"size" json:"size"`
	// MaxIdleTime sets up the interval time of cleaning up goroutines, 0 means never cleanup.
	MaxIdleTime time.Duration `yaml:"maxIdleTime" json:"maxIdleTime"`
}

// SetDefaults set zero values to defautls.
func (c *Config) SetDefaults() {
	if c.GoroutinePoolSize == 0 {
		c.GoroutinePoolSize = runtime.NumCPU() * 200
	}
	if c.Size == 0 {
		c.Size = 2 * 1024 * 1024
	}
}
