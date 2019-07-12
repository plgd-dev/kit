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

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

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
	es     *cqrsMongodb.EventStore
	client *mongo.Client
	config Config

	uniqueIdIsInitialized uint64
}

type Config struct {
	Host            string        `envconfig:"MONGO_HOST" default:"localhost:27017"`
	DatabaseName    string        `envconfig:"MONGO_DATABASE" default:"eventStore"`
	BatchSize       int           `envconfig:"MONGO_BATCH_SIZE" default:"16"`
	MaxPoolSize     uint16        `envconfig:"MONGO_MAX_POOL_SIZE" default:"16"`
	MaxConnIdleTime time.Duration `envconfig:"MONGO_MAX_CONN_IDLE_TIME" default:"240s"`
}

//String return string representation of Config
func (c Config) String() string {
	b, _ := json.MarshalIndent(c, "", "  ")
	return fmt.Sprintf("config: \n%v\n", string(b))
}

//NewEventStore create a event store from configuration
func NewEventStore(config Config, goroutinePoolGo eventstore.GoroutinePoolGoFunc) (*EventStore, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://"+config.Host).SetMaxPoolSize(config.MaxPoolSize).SetMaxConnIdleTime(config.MaxConnIdleTime))
	if err != nil {
		return nil, fmt.Errorf("could not dial database: %v", err)
	}
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return nil, fmt.Errorf("could not dial database: %v", err)
	}

	es, err := cqrsMongodb.NewEventStoreWithClient(ctx, client, config.DatabaseName, "events", config.BatchSize, goroutinePoolGo, cqrsUtils.Marshal, cqrsUtils.Unmarshal, log.Debugf)
	if err != nil {
		return nil, err
	}
	return &EventStore{
		es:     es,
		client: client,
		config: config,
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
	err2 := s.client.Database(s.es.DBName()).Collection(instanceIdsCollection).Drop(ctx)
	if err1 != nil {
		return fmt.Errorf("cannot clear events: %v", err1)
	}
	if err2 != nil && err2 != mongo.ErrNoDocuments {
		return fmt.Errorf("cannot clear sequence number: %v", err2)
	}
	return nil
}

type seqRecord struct {
	AggregateId string `bson:"aggregateid"`
	InstanceId  int64  `bson:"_id"`
}

// GetInstanceId returns int64 that is unique
func (s *EventStore) GetInstanceId(ctx context.Context, aggregateId string) (int64, error) {
	var newInstanceId uint32
	for {
		newInstanceId = rand.Uint32()

		r := seqRecord{
			AggregateId: aggregateId,
			InstanceId:  int64(newInstanceId),
		}

		if _, err := s.client.Database(s.es.DBName()).Collection(instanceIdsCollection).InsertOne(ctx, r); err != nil {
			if cqrsMongodb.IsDup(err) {
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
	if _, err := s.client.Database(s.es.DBName()).Collection(instanceIdsCollection).DeleteOne(ctx, bson.M{"_id": instanceId}); err != nil {
		return fmt.Errorf("cannot remove instance id: %v", err)
	}
	return nil
}

// Close closes the database session.
func (s *EventStore) Close(ctx context.Context) error {
	return s.es.Close(ctx)
}
