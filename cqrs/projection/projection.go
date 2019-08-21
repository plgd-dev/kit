package projection

import (
	"context"
	"fmt"

	"github.com/go-ocf/cqrs"
	"github.com/go-ocf/cqrs/eventbus"
	"github.com/go-ocf/cqrs/eventstore"
	"github.com/go-ocf/kit/log"
)

type Projection struct {
	cqrsProjection *cqrs.Projection

	topicManager *TopicManager
	refCountMap  *RefCountMap
}

func NewProjection(ctx context.Context, name string, store eventstore.EventStore, subscriber eventbus.Subscriber, factoryModel eventstore.FactoryModelFunc, getTopics GetTopicsFunc) (*Projection, error) {
	cqrsProjection, err := cqrs.NewProjection(ctx, store, name, subscriber, factoryModel, log.Debugf)
	if err != nil {
		return nil, fmt.Errorf("cannot create Projection: %v", err)
	}
	return &Projection{
		cqrsProjection: cqrsProjection,
		topicManager:   NewTopicManager(getTopics),
		refCountMap:    NewRefCountMap(),
	}, nil
}

func (p *Projection) ForceUpdate(ctx context.Context, registrationId string, query []eventstore.SnapshotQuery) error {
	_, err := p.refCountMap.Inc(registrationId, false)
	if err != nil {
		return fmt.Errorf("cannot force update projection: %v", err)
	}

	err = p.cqrsProjection.Project(ctx, query)
	if err != nil {
		return fmt.Errorf("cannot force update projection: %v", err)
	}
	_, err = p.refCountMap.Dec(registrationId)
	if err != nil {
		return fmt.Errorf("cannot force update projection: %v", err)
	}
	return nil
}

func (p *Projection) Models(query []eventstore.SnapshotQuery) []eventstore.Model {
	return p.cqrsProjection.Models(query)
}

func (p *Projection) Register(ctx context.Context, registrationId string, query []eventstore.SnapshotQuery) (loaded bool, err error) {
	created, err := p.refCountMap.Inc(registrationId, true)
	if err != nil {
		return false, fmt.Errorf("cannot register device: %v", err)
	}
	if !created {
		return false, nil
	}

	topics, updateSubscriber := p.topicManager.Add(registrationId)

	if updateSubscriber {
		err := p.cqrsProjection.SubscribeTo(topics)
		if err != nil {
			p.refCountMap.Dec(registrationId)
			return false, fmt.Errorf("cannot register device: %v", err)
		}
	}

	err = p.cqrsProjection.Project(ctx, query)
	if err != nil {
		return false, fmt.Errorf("cannot register device: %v", err)
	}

	return true, nil
}

func (p *Projection) Unregister(registrationId string) error {
	deleted, err := p.refCountMap.Dec(registrationId)
	if err != nil {
		return fmt.Errorf("cannot unregister device from projection: %v", err)
	}
	if !deleted {
		return nil
	}

	topics, updateSubscriber := p.topicManager.Remove(registrationId)

	if updateSubscriber {
		err := p.cqrsProjection.SubscribeTo(topics)
		if err != nil {
			log.Errorf("cannot change topics for projection: %v", err)
		}
	}
	return p.cqrsProjection.Forget([]eventstore.SnapshotQuery{
		{GroupId: registrationId},
	})
}
