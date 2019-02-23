// Copyright (c) 2015 - The Event Horizon authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/panjf2000/ants"

	"github.com/go-ocf/cqrs/event"
	"github.com/go-ocf/cqrs/eventstore"
	cqrsMongodb "github.com/go-ocf/cqrs/eventstore/mongodb"
	cqrsUtils "github.com/go-ocf/kit/cqrs"
	"github.com/go-ocf/kit/log"
)

const instanceIdsCollection = "instanceIds"

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

// EventStore implements an EventStore for MongoDB.
type EventStore struct {
	es      *cqrsMongodb.EventStore
	session *mgo.Session
	config  Config

	uniqueIdIsInitialized uint64
}

type Config struct {
	Host         string `envconfig:"MONGO_HOST" default:localhost:27017"`
	DatabaseName string `envconfig:"MONGO_DATABASE" default:"eventStore"`
	BatchSize    int    `envconfig:"MONGO_BATCH_SIZE" default:"128"`
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}

//NewEventStore create a event store from configuration
func NewEventStore(config Config, pool *ants.Pool) (*EventStore, error) {
	session, err := mgo.Dial(config.Host)
	if err != nil {
		return nil, fmt.Errorf("cannot dial to DB: %v", err)
	}

	session.SetMode(mgo.Strong, true)
	session.SetSafe(&mgo.Safe{W: 1})

	es, err := cqrsMongodb.NewEventStoreWithSession(session, config.DatabaseName, "events", config.BatchSize, pool, cqrsUtils.Marshal, cqrsUtils.Unmarshal, log.Debugf)
	if err != nil {
		return nil, err
	}
	return &EventStore{
		es:      es,
		session: session,
		config:  config,
	}, nil
}

func (s *EventStore) Save(ctx context.Context, groupId, aggregateId string, events []event.Event) (concurrencyException bool, err error) {
	return s.es.Save(ctx, groupId, aggregateId, events)
}

func (s *EventStore) SaveSnapshot(ctx context.Context, groupId, aggregateId string, event event.Event) (concurrencyException bool, err error) {
	return s.es.SaveSnapshot(ctx, groupId, aggregateId, event)
}

func (s *EventStore) LoadFromVersion(ctx context.Context, queries []eventstore.VersionQuery, eventHandler event.Handler) error {
	return s.es.LoadFromVersion(ctx, queries, eventHandler)
}

func (s *EventStore) LoadFromSnapshot(ctx context.Context, queries []eventstore.SnapshotQuery, eventHandler event.Handler) error {
	return s.es.LoadFromSnapshot(ctx, queries, eventHandler)
}

// Clear clears the event storage.
func (s *EventStore) Clear(ctx context.Context) error {
	err1 := s.es.Clear(ctx)
	sess := s.session.Copy()
	defer sess.Close()
	err2 := sess.DB(s.es.DBName()).C(instanceIdsCollection).DropCollection()
	if err1 != nil {
		return fmt.Errorf("cannot clear events: %v", err1)
	}
	if err2 != nil && err2 != mgo.ErrNotFound {
		return fmt.Errorf("cannot clear sequence number: %v", err2)
	}
	return nil
}

type seqRecord struct {
	GroupId     string `bson:"groupid"`
	AggregateId string `bson:"aggregateid"`
	InstanceId  int64  `bson:"_id"`
}

// GetInstanceId returns int64 that is unique
func (s *EventStore) GetInstanceId(ctx context.Context, groupId, aggregateId string) (int64, error) {
	sess := s.session.Copy()
	defer sess.Close()
	var newInstanceId uint32
	for {
		newInstanceId = rand.Uint32()

		r := seqRecord{
			GroupId:     groupId,
			AggregateId: aggregateId,
			InstanceId:  int64(newInstanceId),
		}

		if err := sess.DB(s.es.DBName()).C(instanceIdsCollection).Insert(r); err != nil {
			if mgo.IsDup(err) {
				rand.Seed(time.Now().UTC().UnixNano())
			} else {
				return -1, fmt.Errorf("cannot generate instance id: %v", err)
			}
		} else {
			break
		}
	}

	return int64(newInstanceId), nil
}

func (s *EventStore) RemoveInstanceId(ctx context.Context, instanceId int64) error {
	sess := s.session.Copy()
	defer sess.Close()
	if err := sess.DB(s.es.DBName()).C(instanceIdsCollection).Remove(bson.M{"_id": instanceId}); err != nil {
		return fmt.Errorf("cannot removce instance id: %v", err)
	}
	return nil
}

// Close closes the database session.
func (s *EventStore) Close() {
	s.es.Close()
}
