package kafka

import (
	"github.com/Shopify/sarama"
	cqrsKafka "github.com/go-ocf/cqrs/eventbus/kafka"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
)

type Subscriber struct {
	*cqrsKafka.Subscriber
}

//NewPublisher create new Publisher with configuration, proto marshaller and unmarshaller
func NewSubscriber(config Config) (*Subscriber, error) {
	saramaConfig := sarama.NewConfig()
	s, err := cqrsKafka.NewSubscriber(config.Endpoints, saramaConfig, cqrsUtils.Unmarshal, config.ErrFunc)
	if err != nil {
		return nil, err
	}
	return &Subscriber{
		s,
	}, nil
}
