package kafka

import (
	"encoding/json"
	"fmt"

	"github.com/Shopify/sarama"
	cqrsKafka "github.com/go-ocf/cqrs/eventbus/kafka"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
)

type Config struct {
	Endpoints []string `envconfig:"KAFKA_ENDPOINTS" default:"localhost:9092"`
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}

type Publisher struct {
	*cqrsKafka.Publisher
}

// NewPublisher creates new publisher with configuration and proto marshaller.
func NewPublisher(config Config) (*Publisher, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Flush.MaxMessages = 1
	p, err := cqrsKafka.NewPublisher(config.Endpoints, saramaConfig, cqrsUtils.Marshal)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		p,
	}, nil
}

// Close close publisher.
func (p *Publisher) Close() error {
	return p.Publisher.Close()
}
