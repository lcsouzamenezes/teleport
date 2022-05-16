// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: slice.proto

package events

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// SessionSlice is a slice of submitted chunks
type SessionSlice struct {
	// Namespace is a session namespace
	Namespace string `protobuf:"bytes,1,opt,name=Namespace,proto3" json:"Namespace,omitempty"`
	// SessionID is a session ID associated with this chunk
	SessionID string `protobuf:"bytes,2,opt,name=SessionID,proto3" json:"SessionID,omitempty"`
	// Chunks is a list of submitted session chunks
	Chunks []*SessionChunk `protobuf:"bytes,3,rep,name=Chunks,proto3" json:"Chunks,omitempty"`
	// Version specifies session slice version
	Version              int64    `protobuf:"varint,4,opt,name=Version,proto3" json:"Version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionSlice) Reset()         { *m = SessionSlice{} }
func (m *SessionSlice) String() string { return proto.CompactTextString(m) }
func (*SessionSlice) ProtoMessage()    {}
func (*SessionSlice) Descriptor() ([]byte, []int) {
	return fileDescriptor_3fd6ee261cc16ff1, []int{0}
}
func (m *SessionSlice) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *SessionSlice) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_SessionSlice.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *SessionSlice) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionSlice.Merge(m, src)
}
func (m *SessionSlice) XXX_Size() int {
	return m.Size()
}
func (m *SessionSlice) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionSlice.DiscardUnknown(m)
}

var xxx_messageInfo_SessionSlice proto.InternalMessageInfo

func (m *SessionSlice) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *SessionSlice) GetSessionID() string {
	if m != nil {
		return m.SessionID
	}
	return ""
}

func (m *SessionSlice) GetChunks() []*SessionChunk {
	if m != nil {
		return m.Chunks
	}
	return nil
}

func (m *SessionSlice) GetVersion() int64 {
	if m != nil {
		return m.Version
	}
	return 0
}

// SessionChunk is a chunk to be posted in the context of the session
type SessionChunk struct {
	// Time is the occurence of this event
	Time int64 `protobuf:"varint,2,opt,name=Time,proto3" json:"Time,omitempty"`
	// Data is captured data, contains event fields in case of event, session data
	// otherwise
	Data []byte `protobuf:"bytes,3,opt,name=Data,proto3" json:"Data,omitempty"`
	// EventType is event type
	EventType string `protobuf:"bytes,4,opt,name=EventType,proto3" json:"EventType,omitempty"`
	// EventIndex is the event global index
	EventIndex int64 `protobuf:"varint,5,opt,name=EventIndex,proto3" json:"EventIndex,omitempty"`
	// Index is the autoincremented chunk index
	ChunkIndex int64 `protobuf:"varint,6,opt,name=ChunkIndex,proto3" json:"ChunkIndex,omitempty"`
	// Offset is an offset from the previous chunk in bytes
	Offset int64 `protobuf:"varint,7,opt,name=Offset,proto3" json:"Offset,omitempty"`
	// Delay is a delay from the previous event in milliseconds
	Delay                int64    `protobuf:"varint,8,opt,name=Delay,proto3" json:"Delay,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SessionChunk) Reset()         { *m = SessionChunk{} }
func (m *SessionChunk) String() string { return proto.CompactTextString(m) }
func (*SessionChunk) ProtoMessage()    {}
func (*SessionChunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_3fd6ee261cc16ff1, []int{1}
}
func (m *SessionChunk) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *SessionChunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_SessionChunk.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *SessionChunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SessionChunk.Merge(m, src)
}
func (m *SessionChunk) XXX_Size() int {
	return m.Size()
}
func (m *SessionChunk) XXX_DiscardUnknown() {
	xxx_messageInfo_SessionChunk.DiscardUnknown(m)
}

var xxx_messageInfo_SessionChunk proto.InternalMessageInfo

func (m *SessionChunk) GetTime() int64 {
	if m != nil {
		return m.Time
	}
	return 0
}

func (m *SessionChunk) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *SessionChunk) GetEventType() string {
	if m != nil {
		return m.EventType
	}
	return ""
}

func (m *SessionChunk) GetEventIndex() int64 {
	if m != nil {
		return m.EventIndex
	}
	return 0
}

func (m *SessionChunk) GetChunkIndex() int64 {
	if m != nil {
		return m.ChunkIndex
	}
	return 0
}

func (m *SessionChunk) GetOffset() int64 {
	if m != nil {
		return m.Offset
	}
	return 0
}

func (m *SessionChunk) GetDelay() int64 {
	if m != nil {
		return m.Delay
	}
	return 0
}

func init() {
	proto.RegisterType((*SessionSlice)(nil), "events.SessionSlice")
	proto.RegisterType((*SessionChunk)(nil), "events.SessionChunk")
}

func init() { proto.RegisterFile("slice.proto", fileDescriptor_3fd6ee261cc16ff1) }

var fileDescriptor_3fd6ee261cc16ff1 = []byte{
	// 263 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x90, 0x31, 0x4e, 0xc3, 0x30,
	0x14, 0x86, 0x65, 0xdc, 0xba, 0xe4, 0x35, 0x93, 0x55, 0xa1, 0x37, 0xa0, 0x28, 0xea, 0x94, 0x01,
	0x65, 0x80, 0x1b, 0x40, 0x18, 0xba, 0x80, 0xe4, 0x56, 0xec, 0xa6, 0xbc, 0x8a, 0x88, 0x36, 0x89,
	0xea, 0x80, 0xe8, 0x35, 0x38, 0x12, 0x13, 0x23, 0x47, 0x40, 0x39, 0x09, 0xf2, 0x73, 0x20, 0xdd,
	0xfc, 0x7f, 0xdf, 0x2f, 0xff, 0x96, 0x61, 0xea, 0xb6, 0xe5, 0x9a, 0xf2, 0x66, 0x5f, 0xb7, 0xb5,
	0x56, 0xf4, 0x46, 0x55, 0xeb, 0xe6, 0x1f, 0x02, 0xe2, 0x25, 0x39, 0x57, 0xd6, 0xd5, 0xd2, 0x6b,
	0x7d, 0x0e, 0xd1, 0x9d, 0xdd, 0x91, 0x6b, 0xec, 0x9a, 0x50, 0xa4, 0x22, 0x8b, 0xcc, 0x00, 0xbc,
	0xed, 0xdb, 0x8b, 0x02, 0x4f, 0x82, 0xfd, 0x07, 0xfa, 0x02, 0xd4, 0xcd, 0xf3, 0x6b, 0xf5, 0xe2,
	0x50, 0xa6, 0x32, 0x9b, 0x5e, 0xce, 0xf2, 0xb0, 0x92, 0xf7, 0x15, 0x96, 0xa6, 0xef, 0x68, 0x84,
	0xc9, 0x03, 0xed, 0x3d, 0xc7, 0x51, 0x2a, 0x32, 0x69, 0xfe, 0xe2, 0xfc, 0x73, 0x78, 0x14, 0x77,
	0xb5, 0x86, 0xd1, 0xaa, 0xdc, 0x11, 0x2f, 0x4a, 0xc3, 0x67, 0xcf, 0x0a, 0xdb, 0x5a, 0x94, 0xa9,
	0xc8, 0x62, 0xc3, 0x67, 0xff, 0xbc, 0x5b, 0xbf, 0xb8, 0x3a, 0x34, 0xc4, 0x97, 0x46, 0x66, 0x00,
	0x3a, 0x01, 0xe0, 0xb0, 0xa8, 0x9e, 0xe8, 0x1d, 0xc7, 0x7c, 0xd7, 0x11, 0xf1, 0x9e, 0xe7, 0x82,
	0x57, 0xc1, 0x0f, 0x44, 0x9f, 0x81, 0xba, 0xdf, 0x6c, 0x1c, 0xb5, 0x38, 0x61, 0xd7, 0x27, 0x3d,
	0x83, 0x71, 0x41, 0x5b, 0x7b, 0xc0, 0x53, 0xc6, 0x21, 0x5c, 0xc7, 0x5f, 0x5d, 0x22, 0xbe, 0xbb,
	0x44, 0xfc, 0x74, 0x89, 0x78, 0x54, 0xfc, 0xed, 0x57, 0xbf, 0x01, 0x00, 0x00, 0xff, 0xff, 0x87,
	0xfe, 0xfc, 0xe5, 0x85, 0x01, 0x00, 0x00,
}

func (m *SessionSlice) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *SessionSlice) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *SessionSlice) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Version != 0 {
		i = encodeVarintSlice(dAtA, i, uint64(m.Version))
		i--
		dAtA[i] = 0x20
	}
	if len(m.Chunks) > 0 {
		for iNdEx := len(m.Chunks) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Chunks[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintSlice(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x1a
		}
	}
	if len(m.SessionID) > 0 {
		i -= len(m.SessionID)
		copy(dAtA[i:], m.SessionID)
		i = encodeVarintSlice(dAtA, i, uint64(len(m.SessionID)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Namespace) > 0 {
		i -= len(m.Namespace)
		copy(dAtA[i:], m.Namespace)
		i = encodeVarintSlice(dAtA, i, uint64(len(m.Namespace)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *SessionChunk) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *SessionChunk) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *SessionChunk) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Delay != 0 {
		i = encodeVarintSlice(dAtA, i, uint64(m.Delay))
		i--
		dAtA[i] = 0x40
	}
	if m.Offset != 0 {
		i = encodeVarintSlice(dAtA, i, uint64(m.Offset))
		i--
		dAtA[i] = 0x38
	}
	if m.ChunkIndex != 0 {
		i = encodeVarintSlice(dAtA, i, uint64(m.ChunkIndex))
		i--
		dAtA[i] = 0x30
	}
	if m.EventIndex != 0 {
		i = encodeVarintSlice(dAtA, i, uint64(m.EventIndex))
		i--
		dAtA[i] = 0x28
	}
	if len(m.EventType) > 0 {
		i -= len(m.EventType)
		copy(dAtA[i:], m.EventType)
		i = encodeVarintSlice(dAtA, i, uint64(len(m.EventType)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.Data) > 0 {
		i -= len(m.Data)
		copy(dAtA[i:], m.Data)
		i = encodeVarintSlice(dAtA, i, uint64(len(m.Data)))
		i--
		dAtA[i] = 0x1a
	}
	if m.Time != 0 {
		i = encodeVarintSlice(dAtA, i, uint64(m.Time))
		i--
		dAtA[i] = 0x10
	}
	return len(dAtA) - i, nil
}

func encodeVarintSlice(dAtA []byte, offset int, v uint64) int {
	offset -= sovSlice(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *SessionSlice) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Namespace)
	if l > 0 {
		n += 1 + l + sovSlice(uint64(l))
	}
	l = len(m.SessionID)
	if l > 0 {
		n += 1 + l + sovSlice(uint64(l))
	}
	if len(m.Chunks) > 0 {
		for _, e := range m.Chunks {
			l = e.Size()
			n += 1 + l + sovSlice(uint64(l))
		}
	}
	if m.Version != 0 {
		n += 1 + sovSlice(uint64(m.Version))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *SessionChunk) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Time != 0 {
		n += 1 + sovSlice(uint64(m.Time))
	}
	l = len(m.Data)
	if l > 0 {
		n += 1 + l + sovSlice(uint64(l))
	}
	l = len(m.EventType)
	if l > 0 {
		n += 1 + l + sovSlice(uint64(l))
	}
	if m.EventIndex != 0 {
		n += 1 + sovSlice(uint64(m.EventIndex))
	}
	if m.ChunkIndex != 0 {
		n += 1 + sovSlice(uint64(m.ChunkIndex))
	}
	if m.Offset != 0 {
		n += 1 + sovSlice(uint64(m.Offset))
	}
	if m.Delay != 0 {
		n += 1 + sovSlice(uint64(m.Delay))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovSlice(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozSlice(x uint64) (n int) {
	return sovSlice(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *SessionSlice) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowSlice
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: SessionSlice: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: SessionSlice: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Namespace", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSlice
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthSlice
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Namespace = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SessionID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSlice
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthSlice
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SessionID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Chunks", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthSlice
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthSlice
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Chunks = append(m.Chunks, &SessionChunk{})
			if err := m.Chunks[len(m.Chunks)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			m.Version = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Version |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipSlice(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthSlice
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *SessionChunk) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowSlice
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: SessionChunk: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: SessionChunk: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Time", wireType)
			}
			m.Time = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Time |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Data", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthSlice
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthSlice
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Data = append(m.Data[:0], dAtA[iNdEx:postIndex]...)
			if m.Data == nil {
				m.Data = []byte{}
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EventType", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthSlice
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthSlice
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.EventType = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field EventIndex", wireType)
			}
			m.EventIndex = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.EventIndex |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field ChunkIndex", wireType)
			}
			m.ChunkIndex = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.ChunkIndex |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 7:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Offset", wireType)
			}
			m.Offset = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Offset |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 8:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Delay", wireType)
			}
			m.Delay = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Delay |= int64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipSlice(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthSlice
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipSlice(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowSlice
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
					return 0, ErrIntOverflowSlice
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowSlice
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
			if length < 0 {
				return 0, ErrInvalidLengthSlice
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupSlice
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthSlice
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthSlice        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowSlice          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupSlice = fmt.Errorf("proto: unexpected end of group")
)