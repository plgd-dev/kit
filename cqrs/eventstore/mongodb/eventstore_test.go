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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEventStore(t *testing.T) {
	bus, err := NewEventStore(Config{
		Host: "localhost:27017",
	}, nil)
	assert.NoError(t, err)
	assert.NotNil(t, bus)
}

func TestInstanceId(t *testing.T) {
	ctx := context.Background()
	store, err := NewEventStore(Config{
		Host:         "localhost:27017",
		DatabaseName: "test",
	}, nil)
	defer func() {
		store.Clear(ctx)
		store.Close(ctx)
	}()
	assert.NoError(t, err)

	for i := int64(1); i < 10; i++ {
		instanceId, err := store.GetInstanceId(ctx, "b")
		assert.NoError(t, err)
		err = store.RemoveInstanceId(ctx, instanceId)
		assert.NoError(t, err)
	}
}
