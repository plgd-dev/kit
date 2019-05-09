package projection

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/go-ocf/cqrs"
	"github.com/go-ocf/cqrs/eventbus"
	"github.com/go-ocf/cqrs/eventstore"
	"github.com/go-ocf/kit/log"

	raCqrsUtils "github.com/go-ocf/resource-aggregate/cqrs"
)

type GetTopicsFunc func(string) []string

type refCounter struct {
	counter int32
	lock    sync.Mutex
}

type Projection struct {
	cqrsProjection *cqrs.Projection
	getTopics      GetTopicsFunc

	lock   sync.Mutex
	topics map[string]int

	registrationsLock sync.Mutex
	registrations     map[string]*refCounter
}

func NewProjection(ctx context.Context, name string, store eventstore.EventStore, subscriber eventbus.Subscriber, factoryModel eventstore.FactoryModelFunc, getTopics GetTopicsFunc) (*Projection, error) {
	cqrsProjection, err := cqrs.NewProjection(ctx, store, name, subscriber, factoryModel, log.Debugf)
	if err != nil {
		return nil, fmt.Errorf("cannot create Projection: %v", err)
	}
	return &Projection{
		cqrsProjection: cqrsProjection,
		getTopics:      getTopics,
		topics:         make(map[string]int),
		registrations:  make(map[string]*refCounter),
	}, nil
}

func (p *Projection) addTopics(registrationId string) ([]string, bool) {
	var updateSubscriber bool
	var topics []string
	p.lock.Lock()
	defer p.lock.Unlock()
	for _, t := range p.getTopics(registrationId) {
		if _, ok := p.topics[t]; ok {
			p.topics[t]++
		} else {
			updateSubscriber = true
			p.topics[t] = 1
		}
	}
	if updateSubscriber {
		for t := range p.topics {
			topics = append(topics, t)
		}
	}
	return topics, updateSubscriber
}

func (p *Projection) removeTopics(registrationId string) ([]string, bool) {
	var updateSubscriber bool
	var topics []string
	p.lock.Lock()
	defer p.lock.Unlock()
	for _, t := range raCqrsUtils.GetTopics(registrationId) {
		if _, ok := p.topics[t]; ok {
			p.topics[t]--
			if p.topics[t] <= 0 {
				delete(p.topics, t)
				updateSubscriber = true
			}
		}
	}
	if updateSubscriber {
		for t := range p.topics {
			topics = append(topics, t)
		}
	}
	return topics, updateSubscriber
}

func (p *Projection) ForceUpdate(ctx context.Context, registrationId string, query []eventstore.SnapshotQuery) error {
	_, device, err := p.incRefCounter(registrationId, false)
	if err != nil {
		return fmt.Errorf("cannot force update projection: %v", err)
	}
	device.lock.Lock()
	defer device.lock.Unlock()

	err = p.cqrsProjection.Project(ctx, query)
	if err != nil {
		return fmt.Errorf("cannot force update projection: %v", err)
	}
	_, _, err = p.decRefCounter(registrationId)
	if err != nil {
		return fmt.Errorf("cannot force update projection: %v", err)
	}
	return nil
}

func (p *Projection) incRefCounter(registrationId string, create bool) (counter int32, device *refCounter, err error) {
	var ok bool

	p.registrationsLock.Lock()
	defer p.registrationsLock.Unlock()
	if device, ok = p.registrations[registrationId]; !ok {
		if !create {
			return -1, nil, fmt.Errorf("cannot increment reference counter: not found")
		}
		device = &refCounter{}
		p.registrations[registrationId] = device
	}
	counter = atomic.AddInt32(&device.counter, 1)
	return counter, device, nil
}

func (p *Projection) decRefCounter(registrationId string) (counter int32, device *refCounter, err error) {
	var ok bool

	p.registrationsLock.Lock()
	defer p.registrationsLock.Unlock()
	if device, ok = p.registrations[registrationId]; !ok {
		return 0, nil, fmt.Errorf("cannot decrement reference counter: not found")
	}
	counter = atomic.AddInt32(&device.counter, -1)
	if counter == 0 {
		delete(p.registrations, registrationId)
	}

	return counter, device, nil
}

func (p *Projection) Models(query []eventstore.SnapshotQuery) []eventstore.Model {
	return p.cqrsProjection.Models(query)
}

func (p *Projection) Register(ctx context.Context, registrationId string, query []eventstore.SnapshotQuery) (loaded bool, err error) {
	counter, device, err := p.incRefCounter(registrationId, true)
	if err != nil {
		return false, fmt.Errorf("cannot register device: %v", err)
	}
	if counter > 1 {
		return false, nil
	}
	device.lock.Lock()
	defer device.lock.Unlock()

	err = p.cqrsProjection.Project(ctx, query)
	if err != nil {
		return false, fmt.Errorf("cannot register device: %v", err)
	}

	topics, updateSubscriber := p.addTopics(registrationId)

	if updateSubscriber {
		err := p.cqrsProjection.SubscribeTo(topics)
		if err != nil {
			p.decRefCounter(registrationId)
			return false, fmt.Errorf("cannot register device: %v", err)
		}
	}
	return true, nil
}

func (p *Projection) Unregister(registrationId string) error {
	counter, device, err := p.decRefCounter(registrationId)
	if err != nil {
		return fmt.Errorf("cannot unregister device from projection: %v", err)
	}
	if counter > 0 {
		return nil
	}
	device.lock.Lock()
	defer device.lock.Unlock()

	topics, updateSubscriber := p.removeTopics(registrationId)

	if updateSubscriber {
		err := p.cqrsProjection.SubscribeTo(topics)
		if err != nil {
			log.Errorf("cannot change topics for projection: %v", err)
		}
	}

	return nil
}
