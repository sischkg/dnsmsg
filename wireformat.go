package dnsmsg

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type WireFormat []byte

func (w WireFormat) Size() uint32 {
	return uint32(len(w))
}

func (w *WireFormat) AppendUInt8(v uint8) uint32 {
	*w = append(*w, v)
	return 1
}

func (w *WireFormat) AppendUInt16(v uint16) uint32 {
	*w = binary.BigEndian.AppendUint16(*w, v)
	return 2
}

func (w *WireFormat) AppendUInt32(v uint32) uint32 {
	*w = binary.BigEndian.AppendUint32(*w, v)
	return 4
}

func (w *WireFormat) AppendBytes(v []byte) uint32 {
	*w = append(*w, v...)
	return uint32(len(v))
}

func (w *WireFormat) PutUint8(index uint32, v uint8) (uint32, error) {
	if index+1 > w.Size() {
		return 0, fmt.Errorf("not enough to put uint8")
	}
	(*w)[index] = v
	return 1, nil
}

func (w *WireFormat) PutUint16(index uint32, v uint16) (uint32, error) {
	if index+2 > w.Size() {
		return 0, fmt.Errorf("not enough to put uint16")
	}
	(*w)[index] = byte(v >> 8)
	(*w)[index+1] = byte(v & 0xff)
	return 2, nil
}

func (w *WireFormat) PutUint32(index uint32, v uint32) (uint32, error) {
	if index+4 > w.Size() {
		return 0, fmt.Errorf("not enough to put uint32")
	}
	(*w)[index] = byte(v >> 24)
	(*w)[index+1] = byte(0xff & (v >> 16))
	(*w)[index+2] = byte(0xff & (v >> 8))
	(*w)[index+3] = byte(0xff & v)
	return 4, nil
}

func (w *WireFormat) AppendCanonicalDomainname(name Domainname) uint32 {
	var size uint32 = 0
	for _, label := range name {
		*w = append(*w, byte(len(label)))
		size += 1
		*w = append(*w, bytes.ToLower(label)...)
		size += uint32(len(label))
	}
	return size
}

func (w *WireFormat) AppendDomainname(name Domainname, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	for i, suffix := range name.Suffixes() {
		pos, found := db.Find(suffix)
		if found {
			size += w.AppendUInt16(0xc000 + pos)
			return size
		}

		db.Add(suffix, uint16(w.Size()))
		label := name[i]
		size += w.AppendUInt8(uint8(len(label)))
		size += w.AppendBytes(label)
	}
	size += w.AppendUInt8(0)
	return size
}

func (w WireFormat) GetUInt8(i uint32) (uint8, error) {
	if i >= uint32(len(w)) {
		return 0, fmt.Errorf("out of bound access")
	}
	return (w)[i], nil
}

func (w WireFormat) GetUInt16(i uint32) (v uint16, e error) {
	if i > uint32(len(w)+2) {
		return 0, fmt.Errorf("out of bound access")
	}
	binary.Decode((w)[i:i+2], binary.NativeEndian, v)
	e = nil
	return
}

func (w WireFormat) GetUInt32(i uint32) (v uint32, e error) {
	if i > uint32(len(w)+4) {
		return 0, fmt.Errorf("out of bound access")
	}
	binary.Decode((w)[i:i+4], binary.NativeEndian, v)
	e = nil
	return
}

func (w WireFormat) GetBytes(i uint32, size uint32) (v []byte, e error) {
	if i+size > uint32(len(w)) {
		return v, fmt.Errorf("out of bound access")
	}

	return v[i : i+size], nil
}
