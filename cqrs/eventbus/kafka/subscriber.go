package kafka

import (
	"github.com/Shopify/sarama"
	cqrsEventBus "github.com/go-ocf/cqrs/eventbus"
	cqrsKafka "github.com/go-ocf/cqrs/eventbus/kafka"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
)

type Subscriber struct {
	*cqrsKafka.Subscriber
}

// NewSubscriber create new subscriber with configuration and proto unmarshaller.
func NewSubscriber(config Config, goroutinePoolGo cqrsEventBus.GoroutinePoolGoFunc, errFunc cqrsEventBus.ErrFunc) (*Subscriber, error) {
	saramaConfig := sarama.NewConfig()
	s, err := cqrsKafka.NewSubscriber(config.BootstrapServers, saramaConfig, cqrsUtils.Unmarshal, goroutinePoolGo, errFunc)
	if err != nil {
		return nil, err
	}
	return &Subscriber{
		s,
	}, nil
}
