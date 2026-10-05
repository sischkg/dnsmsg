package dnsmsg

import (
	"encoding/binary"
	"fmt"
)

type WireFormat []byte

func (w WireFormat) Size() uint32 {
	return uint32(len(w))
}

func (w *WireFormat) AppendUInt8(v uint8) uint32 {
	if w == nil {
		return 0
	}
	*w = append(*w, v)
	return 1
}

func (w *WireFormat) AppendUInt16(v uint16) uint32 {
	if w == nil {
		return 0
	}
	*w = binary.BigEndian.AppendUint16(*w, v)
	return 2
}

func (w *WireFormat) AppendUInt32(v uint32) uint32 {
	if w == nil {
		return 0
	}
	*w = binary.BigEndian.AppendUint32(*w, v)
	return 4
}

func (w *WireFormat) AppendBytes(v []byte) uint32 {
	if w == nil {
		return 0
	}
	*w = append(*w, v...)
	return uint32(len(v))
}

func (w *WireFormat) PutUint8(index uint32, v uint8) (uint32, error) {
	if w == nil || uint64(index)+1 > uint64(len(*w)) {
		return 0, fmt.Errorf("not enough to put uint8")
	}
	(*w)[index] = v
	return 1, nil
}

func (w *WireFormat) PutUint16(index uint32, v uint16) (uint32, error) {
	if w == nil || uint64(index)+2 > uint64(len(*w)) {
		return 0, fmt.Errorf("not enough to put uint16")
	}
	(*w)[index] = byte(v >> 8)
	(*w)[index+1] = byte(v & 0xff)
	return 2, nil
}

func (w *WireFormat) PutUint32(index uint32, v uint32) (uint32, error) {
	if w == nil || uint64(index)+4 > uint64(len(*w)) {
		return 0, fmt.Errorf("not enough to put uint32")
	}
	(*w)[index] = byte(v >> 24)
	(*w)[index+1] = byte(0xff & (v >> 16))
	(*w)[index+2] = byte(0xff & (v >> 8))
	(*w)[index+3] = byte(0xff & v)
	return 4, nil
}

func (w *WireFormat) AppendCanonicalDomainname(name Domainname) uint32 {
	if w == nil {
		return 0
	}
	wire := name.CanonicalWireFormat()
	if wire == nil {
		return 0
	}
	return w.AppendBytes(wire)
}

// AppendDomainname appends a domain name and uses compression for suffixes
// which have already been written to the message.  The offset in a DNS
// compression pointer has only fourteen bits, so compression is disabled once
// the current message offset no longer fits in that field.
func (w *WireFormat) AppendDomainname(name Domainname, db *NameCompressionDB) uint32 {
	if w == nil {
		return 0
	}
	if name.IsRoot() {
		w.AppendUInt8(0)
		return 1
	}

	var size uint32
	for i, label := range name {
		suffix := name[i:]

		if db != nil {
			if pointer, found := db.Find(suffix); found &&
				uint32(pointer) < w.Size() && uint32(pointer) <= domainnameCompressionMaxOffset {
				size += w.AppendUInt16(0xc000 | pointer)
				return size
			}
			if w.Size() <= domainnameCompressionMaxOffset {
				db.Add(suffix, uint16(w.Size()))
			}
		}

		size += w.AppendUInt8(uint8(len(label)))
		size += w.AppendBytes(label)
	}

	size += w.AppendUInt8(0)
	return size
}

// AppendDomainName appends a DomainName and uses compression for suffixes
// which have already been written to the message.  The offset in a DNS
// compression pointer has only fourteen bits, so compression is disabled
// once the current message offset no longer fits in that field.
func (w *WireFormat) AppendDomainName(name DomainName, db *NameCompressionDB) uint32 {
	if w == nil {
		return 0
	}

	var size uint32
	for i, label := range name.labels {
		if len(label.data) == 0 {
			// The root label terminates the name.
			break
		}

		if db != nil {
			suffix, _ := NewDomainNameFromLabel(name.labels[i:])

			if pointer, found := db.FindDomainName(suffix); found &&
				uint32(pointer) < w.Size() && uint32(pointer) <= domainnameCompressionMaxOffset {
				size += w.AppendUInt16(0xc000 | pointer)
				return size
			}
			if w.Size() <= domainnameCompressionMaxOffset {
				db.AddDomainName(suffix, uint16(w.Size()))
			}
		}

		size += w.AppendUInt8(uint8(label.Size()))
		size += w.AppendBytes(label.data)
	}

	size += w.AppendUInt8(0)
	return size
}

// AppendCanonicalDomainName appends the canonical wire representation of
// name (RFC 4034 Section 6.2: lower-case, uncompressed, terminated by a
// single zero octet) to w. This is the DomainName counterpart of
// AppendCanonicalDomainname.
func (w *WireFormat) AppendCanonicalDomainName(name DomainName) uint32 {
	if w == nil {
		return 0
	}
	return w.AppendBytes(name.CanonicalWireFormat())
}

func (w WireFormat) GetUInt8(i uint32) (uint8, error) {
	if i >= uint32(len(w)) {
		return 0, fmt.Errorf("out of bound access")
	}
	return (w)[i], nil
}

func (w WireFormat) GetUInt16(i uint32) (v uint16, e error) {
	if uint64(i)+2 > uint64(len(w)) {
		return 0, fmt.Errorf("out of bound access")
	}
	v = (uint16(w[i]) << 8) | uint16(w[i+1])
	return v, nil
}

func (w WireFormat) GetUInt32(i uint32) (v uint32, e error) {
	if uint64(i)+4 > uint64(len(w)) {
		return 0, fmt.Errorf("out of bound access")
	}
	v = (uint32(w[i]) << 24) | (uint32(w[i+1]) << 16) | (uint32(w[i+2]) << 8) | uint32(w[i+3])
	return v, nil
}

func (w WireFormat) GetBytes(i uint32, size uint32) (v []byte, e error) {
	if uint64(i)+uint64(size) > uint64(len(w)) {
		return nil, fmt.Errorf("out of bound access")
	}

	return w[i : i+size], nil
}

func (w WireFormat) String() string {
	var s string
	for _, b := range w {
		s += fmt.Sprintf("%02x ", b)
	}
	return s
}
