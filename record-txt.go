package dnsmsg

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RecordTXT represents a TXT (text) record per RFC 1035 Section 3.3.14.
//
// TXT RDATA wire format:
//
//	<character-string> <character-string> ...
//
// A <character-string> is one length octet followed by that many octets
// (RFC 1035 Section 3.3), so it holds 0 to 255 octets.  The RDATA is one
// or more character-strings.  The text is not interpreted: the octets are
// kept exactly as they appear on the wire.  A character-string longer than
// 255 octets cannot be encoded as a single string and is written as several
// consecutive character-strings.
type RecordTXT struct {
	Strings [][]byte
}

const txtMaxStringLength = 255

func (r RecordTXT) Type() ResourceType {
	return TYPE_TXT
}

// String returns the record in presentation format: the character-strings
// separated by spaces, each enclosed in double quotes.  Inside a quoted
// string '"' and '\' are backslash-escaped and non-printable octets are
// printed as three-digit decimal escapes such as "\065"; the other printable
// octets, including spaces and '.', are printed as-is.
func (r RecordTXT) String() string {
	parts := make([]string, 0, len(r.Strings))
	for _, s := range r.Strings {
		parts = append(parts, quoteCharacterString(s))
	}
	return strings.Join(parts, " ")
}

func (r RecordTXT) CanonicalWireFormat() []byte {
	w := new(WireFormat)
	r.AppendCanonicalWireFormat(w)
	return *w
}

// AppendWireFormat writes each character-string as its length octet followed
// by its octets.  A character-string holds at most 255 octets (RFC 1035
// Section 3.3), so a longer string is written as several consecutive
// character-strings of at most 255 octets each, the way a name server
// publishes a text longer than 255 octets.  TXT RDATA holds no domain
// names, so no name compression is involved and db is unused.
func (r RecordTXT) AppendWireFormat(w *WireFormat, db *NameCompressionDB) uint32 {
	var size uint32 = 0
	for _, s := range r.Strings {
		for {
			n := len(s)
			if n > txtMaxStringLength {
				n = txtMaxStringLength
			}
			size += w.AppendUInt8(uint8(n))
			size += w.AppendBytes(s[:n])
			s = s[n:]
			if len(s) == 0 {
				break
			}
		}
	}
	return size
}

// AppendCanonicalWireFormat writes the RDATA unchanged: the canonical form
// of RFC 4034 Section 6.2 transforms the domain names in RDATA, and a TXT
// RDATA holds none, so the character-strings are written as stored.  A
// character-string longer than 255 octets is split as in AppendWireFormat.
func (r RecordTXT) AppendCanonicalWireFormat(w *WireFormat) uint32 {
	return r.AppendWireFormat(w, nil)
}

// MarshalJSON encodes the record as a JSON object.  The character-strings
// are octet strings, so they are encoded as base64 strings.
func (r RecordTXT) MarshalJSON() ([]byte, error) {
	stringsJSON := make([]string, 0, len(r.Strings))
	for _, s := range r.Strings {
		stringsJSON = append(stringsJSON, encodeBase64(s))
	}
	return json.Marshal(map[string]any{
		"Strings": stringsJSON,
	})
}

// UnmarshalJSON decodes the record from the JSON object MarshalJSON
// produces, taking each character-string from its base64 string.
func (r *RecordTXT) UnmarshalJSON(data []byte) error {
	var fields struct {
		Strings []string `json:"Strings"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("cannot parse TXT record: %w", err)
	}
	var stringsDecoded [][]byte
	for _, s := range fields.Strings {
		octets, err := decodeBase64(s)
		if err != nil {
			return fmt.Errorf("invalid TXT character-string %q: %w", s, err)
		}
		stringsDecoded = append(stringsDecoded, octets)
	}
	r.Strings = stringsDecoded
	return nil
}

// NewRecordTXT creates a new RecordTXT from the given character-strings.
// Each string is an octet string of 0 to 255 octets; the record holds one
// or more character-strings.  A string longer than 255 octets is written
// as several consecutive character-strings.
func NewRecordTXT(strs ...[]byte) RecordTXT {
	return RecordTXT{Strings: strs}
}

// NewRecordTXTFromString parses a TXT record from a presentation-format
// string: one or more character-strings separated by white space.  A string
// enclosed in double quotes may contain spaces; an unquoted string ends at
// white space or a quote.  Inside either form a backslash introduces an
// escape: three decimal digits denote that octet (RFC 4343) and a backslash
// before any other character quotes it.  A quoted empty string denotes an
// empty character-string.
// Format: <character-string> [ <character-string> ... ]
func NewRecordTXTFromString(s string) (r RecordTXT, err error) {
	for pos := 0; pos < len(s); {
		if isTXTDelimiter(s[pos]) {
			pos++
			continue
		}

		var str []byte
		var next int
		if s[pos] == '"' {
			str, next, err = parseQuotedCharacterString(s, pos)
		} else {
			str, next, err = parseUnquotedCharacterString(s, pos)
		}
		if err != nil {
			r = RecordTXT{}
			return
		}
		r.Strings = append(r.Strings, str)
		pos = next
	}

	if len(r.Strings) == 0 {
		err = fmt.Errorf("TXT record %q has no character-strings", s)
		return
	}
	return
}

// ParseRecordTXT parses a TXT record from the wire format.  The
// character-strings are read from begin up to end, the RDLENGTH-derived end
// of the RDATA, so the parsed record is bounded by its own RDLENGTH rather
// than by the remainder of the message.  An RDATA of zero character-strings
// (RDLENGTH 0), and a length octet describing a character-string that does
// not fit in the remaining RDATA, are errors.
func ParseRecordTXT(w WireFormat, begin uint32, end uint32) (r RecordTXT, pos uint32, err error) {
	var p uint32 = begin

	if end > uint32(w.Size()) {
		err = fmt.Errorf("invalid TXT record RDATA size")
		return
	}

	for p < end {
		length, e := w.GetUInt8(p)
		if e != nil {
			err = fmt.Errorf("cannot parse character-string length: %w", e)
			return
		}
		p += 1
		if uint32(length) > end-p {
			err = fmt.Errorf("character-string exceeds RDATA(length: %d, remaining: %d)", length, end-p)
			return
		}
		str, e := w.GetBytes(p, uint32(length))
		if e != nil {
			err = fmt.Errorf("cannot parse character-string: %w", e)
			return
		}
		p += uint32(length)

		r.Strings = append(r.Strings, str)
	}

	if len(r.Strings) == 0 {
		err = fmt.Errorf("TXT record has no character-strings")
		return
	}

	pos = end
	return
}

// quoteCharacterString returns s as a quoted presentation-format
// character-string, following the escaping rules of RecordTXT.String.
func quoteCharacterString(s []byte) string {
	var buf strings.Builder
	buf.Grow(len(s) + 2)
	buf.WriteByte('"')
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			buf.WriteByte('\\')
			buf.WriteByte(c)
		case c >= 0x20 && c <= 0x7e:
			buf.WriteByte(c)
		default:
			buf.WriteByte('\\')
			buf.WriteByte('0' + c/100)
			buf.WriteByte('0' + (c/10)%10)
			buf.WriteByte('0' + c%10)
		}
	}
	buf.WriteByte('"')
	return buf.String()
}

// isTXTDelimiter reports whether c separates two character-strings in
// presentation format.
func isTXTDelimiter(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// parseQuotedCharacterString parses a character-string enclosed in double
// quotes at pos in s, and returns the octets and the offset just past the
// closing quote.
func parseQuotedCharacterString(s string, pos int) ([]byte, int, error) {
	// The empty non-nil slice keeps the result consistent with
	// ParseRecordTXT, whose zero-length character-string is also non-nil.
	str := []byte{}
	pos++ // opening quote
	for pos < len(s) && s[pos] != '"' {
		var octet byte
		var next int
		if s[pos] == '\\' {
			var err error
			octet, next, err = parsePresentationOctet(s, pos)
			if err != nil {
				return nil, pos, err
			}
		} else {
			octet = s[pos]
			next = pos + 1
		}
		if len(str) >= txtMaxStringLength {
			return nil, pos, fmt.Errorf("character-string is too long(length exceeds %d)", txtMaxStringLength)
		}
		str = append(str, octet)
		pos = next
	}
	if pos >= len(s) {
		return nil, pos, fmt.Errorf("unterminated character-string in %q", s)
	}
	return str, pos + 1, nil
}

// parseUnquotedCharacterString parses a character-string not enclosed in
// quotes at pos in s.  It ends at white space, a quote, or the end of s.
func parseUnquotedCharacterString(s string, pos int) ([]byte, int, error) {
	var str []byte
	for pos < len(s) && !isTXTDelimiter(s[pos]) && s[pos] != '"' {
		var octet byte
		var next int
		if s[pos] == '\\' {
			var err error
			octet, next, err = parsePresentationOctet(s, pos)
			if err != nil {
				return nil, pos, err
			}
		} else {
			octet = s[pos]
			next = pos + 1
		}
		if len(str) >= txtMaxStringLength {
			return nil, pos, fmt.Errorf("character-string is too long(length exceeds %d)", txtMaxStringLength)
		}
		str = append(str, octet)
		pos = next
	}
	return str, pos, nil
}
