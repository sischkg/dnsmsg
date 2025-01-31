package dnsmsg

import (
	"bytes"
	"fmt"
)

type Domainname [][]byte

type NameCompressionDB struct {
	nameToPointer map[[DOMAINNAME_MAX_LENGTH]byte]uint16
}

func NewCanonicalDomainnameFromBytes(msg []byte) (Domainname, error) {
	var name Domainname

	for pos := uint32(0); pos < uint32(len(msg)); {
		count := uint32(msg[pos])
		pos++

		if count == 0 {
			return name, nil
		}
		if (count & 0xc) == 0xc {
			return name, fmt.Errorf("name compression not supported")
		}

		if pos+count >= uint32(len(msg)) {
			return name, fmt.Errorf("out of bound in parsing domainname(cannot read label)")
		}
		var label []byte
		for i := 0; i < int(count); i++ {
			label = append(label, msg[pos])
			pos++
		}
		name = append(name, label)
	}
	return name, fmt.Errorf("invalid domainname(not terminated)")
}

func NewDomainnameFromWireFormat(msg []byte, begin uint32) (Domainname, uint32, error) {
	var name Domainname

	if begin >= uint32(len(msg)) {
		return name, begin, fmt.Errorf("out of bound in parsing domainname")
	}

	for pos := begin; pos < uint32(len(msg)); {

		count := uint32(msg[pos])
		pos++

		if count == 0 {
			return name, pos, nil
		}
		if (count & 0xc) == 0xc {
			if pos >= uint32(len(msg)) {
				return name, pos, fmt.Errorf("out of bound in parsing domainname(cannot read offset)")
			}
			offset := (count-0xc)<<8 + uint32(msg[pos])
			pos++

			if offset >= begin {
				return name, pos, fmt.Errorf("invalid domainname(maybe loop)")
			}
			suffix, _, err := NewDomainnameFromWireFormat(msg, uint32(offset))
			if err != nil {
				return name, pos, err
			}
			name = append(name, suffix...)
			return name, pos, nil
		}

		if pos+count >= uint32(len(msg)) {
			return name, pos, fmt.Errorf("out of bound in parsing domainname(cannot read label)")
		}
		var label []byte
		for i := 0; i < int(count); i++ {
			label = append(label, msg[pos])
			pos++
		}
		name = append(name, label)
	}
	return name, begin, fmt.Errorf("invalid domainname(not terminated)")
}

func NewDomainname(name string) (Domainname, error) {
	var d Domainname

	var label []byte
	escaped := false
	var length int = 0

	for _, c := range name {
		if c == '\\' && !escaped {
			escaped = true
		} else if c == '.' && !escaped {
			d = append(d, label)
			length += 1
			label = []byte{}
		} else {
			label = append(label, byte(c))
			length += 1
			escaped = false
		}
	}
	length += 1 // "root label "."

	if escaped {
		return d, fmt.Errorf("last character of %s is \\", name)
	}
	if length > 255 {
		return d, fmt.Errorf("domainname %s is too long(length: %d)", name, length)
	}

	return d, nil
}

func (name *Domainname) String() string {
	var buf bytes.Buffer

	for _, label := range *name {
		for _, c := range label {
			if c == '.' {
				buf.WriteByte('\\')
			}
			buf.WriteByte(c)
		}
		buf.WriteByte('.')
	}

	return buf.String()
}

func (name *Domainname) CanonicalWireFormat() []byte {
	var msg []byte

	for _, label := range *name {
		msg = append(msg, byte(len(label)))
		msg = append(msg, bytes.ToLower(label)...)
	}

	return msg
}

func (name *Domainname) Size() uint32 {
	var size uint32
	for _, label := range *name {
		size += uint32(1 + len(label))
	}
	size += 1
	return size
}

func (name *Domainname) DBKey() [DOMAINNAME_MAX_LENGTH]byte {
	var msg [DOMAINNAME_MAX_LENGTH]byte

	i := 0
	for _, label := range *name {
		msg[i] = byte(len(label))
		i += 1
		for _, c := range bytes.ToLower(label) {
			msg[i] = c
			i += 1
		}
	}
	msg[i] = 0

	return msg
}

func (name *Domainname) Suffixes() (suffixes []Domainname) {
	for i := range *name {
		suffixes = append(suffixes, (*name)[i:len(*name)])
	}
	return
}

func NewNameCompressionDB() *NameCompressionDB {
	db := new(NameCompressionDB)
	db.nameToPointer = make(map[[DOMAINNAME_MAX_LENGTH]byte]uint16)
	return db
}

func (db *NameCompressionDB) Find(name Domainname) (pointer uint16, found bool) {
	key := name.DBKey()
	pointer, found = db.nameToPointer[key]
	return
}

func (db *NameCompressionDB) Add(name Domainname, p uint16) {
	db.nameToPointer[name.DBKey()] = p
}
