package test

import (
	"fmt"

	"github.com/go-ocf/cqrs/event"
	httpUtils "github.com/go-ocf/kit/http"
	"github.com/go-ocf/resource-aggregate/cqrs/events"
	resources "github.com/go-ocf/resource-aggregate/protobuf"
	protoEvents "github.com/go-ocf/resource-aggregate/protobuf/events"
)

func MakeResourcePublishedEvent(version uint64, resource resources.Resource) event.EventUnmarshaler {
	rp := events.ResourcePublished{
		ResourcePublished: protoEvents.ResourcePublished{
			Id:       resource.Id,
			Resource: &resource,
			AuditContext: &resources.AuditContext{
				UserId:   "userId",
				DeviceId: resource.DeviceId,
			},
		},
	}
	return event.EventUnmarshaler{
		Version:     version,
		EventType:   httpUtils.ProtobufContentType(&protoEvents.ResourcePublished{}),
		AggregateId: rp.Id,
		Unmarshal: func(v interface{}) error {
			if x, ok := v.(*events.ResourcePublished); ok {
				*x = rp
				return nil
			}
			return fmt.Errorf("cannot unmarshal event")
		},
	}
}

func MakeResourceUnpublishedEvent(version uint64, id, deviceID string) event.EventUnmarshaler {
	ru := events.ResourceUnpublished{
		ResourceUnpublished: protoEvents.ResourceUnpublished{
			Id: id,
			AuditContext: &resources.AuditContext{
				UserId:   "userId",
				DeviceId: deviceID,
			},
		},
	}
	return event.EventUnmarshaler{
		Version:     version,
		EventType:   httpUtils.ProtobufContentType(&protoEvents.ResourceUnpublished{}),
		AggregateId: ru.Id,
		Unmarshal: func(v interface{}) error {
			if x, ok := v.(*events.ResourceUnpublished); ok {
				*x = ru
				return nil
			}
			return fmt.Errorf("cannot unmarshal event")
		},
	}
}

func MakeResourceStateSnapshotTaken(version uint64, isPublished bool, resource resources.Resource, content resources.Content) event.EventUnmarshaler {
	rs := events.NewResourceStateSnapshotTaken(resource.DeviceId, resource.Id)
	rs.Resource = &resource
	rs.IsPublished = isPublished
	rs.Content = &content

	return event.EventUnmarshaler{
		Version:     version,
		EventType:   httpUtils.ProtobufContentType(&protoEvents.ResourceStateSnapshotTaken{}),
		AggregateId: rs.Id,
		Unmarshal: func(v interface{}) error {
			if x, ok := v.(*events.ResourceStateSnapshotTaken); ok {
				*x = *rs
				return nil
			}
			return fmt.Errorf("cannot unmarshal event")
		},
	}
}

func MakeResourceContentUpdatePending(version uint64, deviceId, resourceId string, content resources.Content) event.EventUnmarshaler {
	rc := events.ResourceContentUpdatePending{
		ResourceContentUpdatePending: protoEvents.ResourceContentUpdatePending{
			Id:      resourceId,
			Content: &content,
			AuditContext: &resources.AuditContext{
				UserId:   "userId",
				DeviceId: deviceId,
			},
		},
	}
	return event.EventUnmarshaler{
		Version:     version,
		EventType:   httpUtils.ProtobufContentType(&protoEvents.ResourceContentUpdatePending{}),
		AggregateId: rc.Id,
		Unmarshal: func(v interface{}) error {
			if x, ok := v.(*events.ResourceContentUpdatePending); ok {
				*x = rc
				return nil
			}
			return fmt.Errorf("cannot unmarshal event")
		},
	}
}

func MakeResourceContentUpdateProcessed(version uint64, deviceId, resourceId string, status resources.Status, content resources.Content) event.EventUnmarshaler {
	rc := events.ResourceContentUpdateProcessed{
		ResourceContentUpdateProcessed: protoEvents.ResourceContentUpdateProcessed{
			Id:      resourceId,
			Content: &content,
			Status:  status,
			AuditContext: &resources.AuditContext{
				UserId:   "userId",
				DeviceId: deviceId,
			},
		},
	}
	return event.EventUnmarshaler{
		Version:     version,
		EventType:   httpUtils.ProtobufContentType(&protoEvents.ResourceContentUpdateProcessed{}),
		AggregateId: rc.Id,
		Unmarshal: func(v interface{}) error {
			if x, ok := v.(*events.ResourceContentUpdateProcessed); ok {
				*x = rc
				return nil
			}
			return fmt.Errorf("cannot unmarshal event")
		},
	}
}

func MakeResourceContentChangedEvent(version uint64, id, deviceID string, content resources.Content) event.EventUnmarshaler {
	ru := events.ResourceContentChanged{
		ResourceContentChanged: protoEvents.ResourceContentChanged{
			Id: id,
			AuditContext: &resources.AuditContext{
				UserId:   "userId",
				DeviceId: deviceID,
			},
			Content: &content,
		},
	}
	return event.EventUnmarshaler{
		Version:     version,
		EventType:   httpUtils.ProtobufContentType(&protoEvents.ResourceContentChanged{}),
		AggregateId: ru.Id,
		Unmarshal: func(v interface{}) error {
			if x, ok := v.(*events.ResourceContentChanged); ok {
				*x = ru
				return nil
			}
			return fmt.Errorf("cannot unmarshal event")
		},
	}
}
