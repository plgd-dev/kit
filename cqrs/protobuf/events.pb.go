// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: events.proto

package protobuf // import "github.com/go-ocf/kit/cqrs/protobuf"

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type AuditContext struct {
	UserId        string `protobuf:"bytes,1,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	DeviceId      string `protobuf:"bytes,2,opt,name=device_id,json=deviceId,proto3" json:"device_id,omitempty"`
	CorrelationId string `protobuf:"bytes,3,opt,name=correlation_id,json=correlationId,proto3" json:"correlation_id,omitempty"`
}

func (m *AuditContext) Reset()         { *m = AuditContext{} }
func (m *AuditContext) String() string { return proto.CompactTextString(m) }
func (*AuditContext) ProtoMessage()    {}
func (*AuditContext) Descriptor() ([]byte, []int) {
	return fileDescriptor_events_01364b4cfe14ac9d, []int{0}
}
func (m *AuditContext) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AuditContext) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AuditContext.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *AuditContext) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AuditContext.Merge(dst, src)
}
func (m *AuditContext) XXX_Size() int {
	return m.Size()
}
func (m *AuditContext) XXX_DiscardUnknown() {
	xxx_messageInfo_AuditContext.DiscardUnknown(m)
}

var xxx_messageInfo_AuditContext proto.InternalMessageInfo

func (m *AuditContext) GetUserId() string {
	if m != nil {
		return m.UserId
	}
	return ""
}

func (m *AuditContext) GetDeviceId() string {
	if m != nil {
		return m.DeviceId
	}
	return ""
}

func (m *AuditContext) GetCorrelationId() string {
	if m != nil {
		return m.CorrelationId
	}
	return ""
}

type EventMetadata struct {
	Version     uint64 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	TimestampMs uint64 `protobuf:"varint,2,opt,name=timestamp_ms,json=timestampMs,proto3" json:"timestamp_ms,omitempty"`
}

func (m *EventMetadata) Reset()         { *m = EventMetadata{} }
func (m *EventMetadata) String() string { return proto.CompactTextString(m) }
func (*EventMetadata) ProtoMessage()    {}
func (*EventMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_events_01364b4cfe14ac9d, []int{1}
}
func (m *EventMetadata) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *EventMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_EventMetadata.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *EventMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_EventMetadata.Merge(dst, src)
}
func (m *EventMetadata) XXX_Size() int {
	return m.Size()
}
func (m *EventMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_EventMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_EventMetadata proto.InternalMessageInfo

func (m *EventMetadata) GetVersion() uint64 {
	if m != nil {
		return m.Version
	}
	return 0
}

func (m *EventMetadata) GetTimestampMs() uint64 {
	if m != nil {
		return m.TimestampMs
	}
	return 0
}

func init() {
	proto.RegisterType((*AuditContext)(nil), "ocf.cloud.AuditContext")
	proto.RegisterType((*EventMetadata)(nil), "ocf.cloud.EventMetadata")
}
func (m *AuditContext) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AuditContext) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.UserId) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintEvents(dAtA, i, uint64(len(m.UserId)))
		i += copy(dAtA[i:], m.UserId)
	}
	if len(m.DeviceId) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintEvents(dAtA, i, uint64(len(m.DeviceId)))
		i += copy(dAtA[i:], m.DeviceId)
	}
	if len(m.CorrelationId) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintEvents(dAtA, i, uint64(len(m.CorrelationId)))
		i += copy(dAtA[i:], m.CorrelationId)
	}
	return i, nil
}

func (m *EventMetadata) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *EventMetadata) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Version != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintEvents(dAtA, i, uint64(m.Version))
	}
	if m.TimestampMs != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintEvents(dAtA, i, uint64(m.TimestampMs))
	}
	return i, nil
}

func encodeVarintEvents(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *AuditContext) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.UserId)
	if l > 0 {
		n += 1 + l + sovEvents(uint64(l))
	}
	l = len(m.DeviceId)
	if l > 0 {
		n += 1 + l + sovEvents(uint64(l))
	}
	l = len(m.CorrelationId)
	if l > 0 {
		n += 1 + l + sovEvents(uint64(l))
	}
	return n
}

func (m *EventMetadata) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Version != 0 {
		n += 1 + sovEvents(uint64(m.Version))
	}
	if m.TimestampMs != 0 {
		n += 1 + sovEvents(uint64(m.TimestampMs))
	}
	return n
}

func sovEvents(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozEvents(x uint64) (n int) {
	return sovEvents(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *AuditContext) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEvents
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AuditContext: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AuditContext: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthEvents
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.UserId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DeviceId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthEvents
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DeviceId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CorrelationId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthEvents
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CorrelationId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipEvents(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthEvents
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *EventMetadata) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEvents
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: EventMetadata: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: EventMetadata: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			m.Version = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Version |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field TimestampMs", wireType)
			}
			m.TimestampMs = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.TimestampMs |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipEvents(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthEvents
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipEvents(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowEvents
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowEvents
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthEvents
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowEvents
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipEvents(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthEvents = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowEvents   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("events.proto", fileDescriptor_events_01364b4cfe14ac9d) }

var fileDescriptor_events_01364b4cfe14ac9d = []byte{
	// 259 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x90, 0xc1, 0x4a, 0xf3, 0x40,
	0x14, 0x85, 0x93, 0xff, 0x2f, 0xad, 0x19, 0x53, 0x17, 0xb3, 0xb1, 0x20, 0x0c, 0x5a, 0x10, 0x5c,
	0x68, 0xb2, 0x70, 0xe9, 0x4a, 0x45, 0x21, 0x60, 0x37, 0x59, 0xba, 0x29, 0xc9, 0xcc, 0x4d, 0x1d,
	0xda, 0xe4, 0xd6, 0x99, 0x3b, 0xc1, 0xc7, 0xf0, 0xb1, 0x5c, 0x76, 0xe9, 0x52, 0x92, 0x17, 0x91,
	0x8c, 0x54, 0xdc, 0x9d, 0xf3, 0x9d, 0x03, 0xe7, 0x72, 0x59, 0x0c, 0x2d, 0x34, 0x64, 0x93, 0xad,
	0x41, 0x42, 0x1e, 0xa1, 0xac, 0x12, 0xb9, 0x41, 0xa7, 0xe6, 0x6b, 0x16, 0xdf, 0x3a, 0xa5, 0xe9,
	0x1e, 0x1b, 0x82, 0x37, 0xe2, 0xc7, 0x6c, 0xe2, 0x2c, 0x98, 0xa5, 0x56, 0xb3, 0xf0, 0x34, 0xbc,
	0x88, 0xf2, 0xf1, 0x60, 0x33, 0xc5, 0x4f, 0x58, 0xa4, 0xa0, 0xd5, 0x12, 0x86, 0xe8, 0x9f, 0x8f,
	0x0e, 0x7e, 0x40, 0xa6, 0xf8, 0x39, 0x3b, 0x92, 0x68, 0x0c, 0x6c, 0x0a, 0xd2, 0xd8, 0x0c, 0x8d,
	0xff, 0xbe, 0x31, 0xfd, 0x43, 0x33, 0x35, 0x7f, 0x62, 0xd3, 0x87, 0xe1, 0x8e, 0x05, 0x50, 0xa1,
	0x0a, 0x2a, 0xf8, 0x8c, 0x4d, 0x5a, 0x30, 0x56, 0x63, 0xe3, 0xd7, 0x46, 0xf9, 0xde, 0xf2, 0x33,
	0x16, 0x93, 0xae, 0xc1, 0x52, 0x51, 0x6f, 0x97, 0xb5, 0xf5, 0x8b, 0xa3, 0xfc, 0xf0, 0x97, 0x2d,
	0xec, 0xdd, 0xe3, 0x47, 0x27, 0xc2, 0x5d, 0x27, 0xc2, 0xaf, 0x4e, 0x84, 0xef, 0xbd, 0x08, 0x76,
	0xbd, 0x08, 0x3e, 0x7b, 0x11, 0x3c, 0x5f, 0xae, 0x34, 0xbd, 0xb8, 0x32, 0x91, 0x58, 0xa7, 0x2b,
	0xbc, 0x42, 0x59, 0xa5, 0x6b, 0x4d, 0xa9, 0x7c, 0x35, 0x36, 0xf5, 0x1f, 0x28, 0x5d, 0x75, 0xb3,
	0x17, 0xe5, 0xd8, 0xab, 0xeb, 0xef, 0x00, 0x00, 0x00, 0xff, 0xff, 0xd8, 0x89, 0x4f, 0xcf, 0x24,
	0x01, 0x00, 0x00,
}
