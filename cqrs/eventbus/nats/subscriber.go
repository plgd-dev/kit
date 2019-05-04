package nats

import (
	cqrsNats "github.com/go-ocf/cqrs/eventbus/nats"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
	"github.com/go-ocf/kit/log"
)

type Subscriber struct {
	*cqrsNats.Subscriber
}

// NewSubscriber create new Subscriber with proto unmarshaller.
func NewSubscriber(config Config) (*Subscriber, error) {
	s, err := cqrsNats.NewSubscriber(config.URL, cqrsUtils.Unmarshal, func(err error) {
		log.Errorf("%v", err)
	}, config.Options...)
	if err != nil {
		return nil, err
	}
	return &Subscriber{
		s,
	}, nil
}

// Close closes the publisher.
func (p *Subscriber) Close() {
	p.Subscriber.Close()
}
