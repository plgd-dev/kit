package kafka

import (
	"github.com/Shopify/sarama"
	cqrsKafka "github.com/go-ocf/cqrs/eventbus/kafka"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
)

type Publisher struct {
	*cqrsKafka.Publisher
}

// NewPublisher creates new publisher with configuration and proto marshaller.
func NewPublisher(config Config) (*Publisher, error) {
	saramaConfig := sarama.NewConfig()
	saramaConfig.Producer.Flush.MaxMessages = 1
	p, err := cqrsKafka.NewPublisher(config.BootstrapServers, saramaConfig, cqrsUtils.Marshal)
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
