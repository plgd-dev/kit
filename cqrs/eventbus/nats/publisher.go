package nats

import (
	cqrsNats "github.com/go-ocf/cqrs/eventbus/nats"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
)

type Publisher struct {
	*cqrsNats.Publisher
}

// NewPublisher creates new Publisher with configuration proto marshaller.
func NewPublisher(config Config) (*Publisher, error) {
	p, err := cqrsNats.NewPublisher(config.URL, cqrsUtils.Marshal, config.Options...)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		p,
	}, nil
}

// Close closes the publisher.
func (p *Publisher) Close() {
	p.Publisher.Close()
}
