package dnsmsg

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// DNSSECKeyFileName is the identity that a dnssec-keygen key file name
// records.  BIND's dnssec-keygen names the two files of a key
// "K<owner name>+<algorithm>+<key tag>.key" and
// "K<owner name>+<algorithm>+<key tag>.private", and this struct holds the
// three fields between the "K" prefix and the file suffix.  Use
// NewDNSSECKeyFileNameFromString to obtain one from a file name; no file is
// opened, only the name is read.
type DNSSECKeyFileName struct {
	// BaseName is the key files' base name with any ".key" or ".private"
	// suffix removed, spelled as it appeared in the parsed name.  Appending
	// ".key" or ".private" to it gives the two file names, and it is the
	// value ReadDNSSECKeyPair and ReadDNSSECKeyFiles accept.
	BaseName string

	// Name is the key's owner name: the first field of the file name, the
	// zone whose DNSKEY this key signs when the key is a zone key.
	Name DomainName

	// Algorithm is the key's DNSSEC algorithm number: the second field of
	// the file name, written as decimal digits.  The matching
	// DNSSECAlgorithm constants are defined in dnssec.go.
	Algorithm uint8

	// KeyTag is the key tag dnssec-keygen computed for the key: the third
	// field of the file name, written as decimal digits.  It equals
	// DNSSECKeyTag over the key's DNSKEY RDATA, so a caller can match it
	// against RecordRRSIG.KeyTag.
	KeyTag uint16
}

// NewDNSSECKeyFileNameFromString parses a dnssec-keygen key file name and
// returns the owner name, algorithm and key tag it records.  The input may be
// a full path or a bare file name, with or without the ".key" or ".private"
// suffix: any directory part is dropped, and a trailing lower-case ".key" or
// ".private" suffix is removed.  What remains must be spelled as dnssec-keygen
// writes it: a "K" prefix followed by the owner name in presentation format,
// then the algorithm and the key tag as decimal fields separated by "+" (for
// example "Kexample.com.+008+12345").  The algorithm must fit in 8 bits and
// the key tag in 16 bits; leading zeroes are accepted but not required.  A
// differently spelled suffix, a name without the "K" prefix, a field count
// other than three, and an unparseable field are all errors that name the
// part of the name that caused them.  No file is opened or required to exist;
// this reads the name only.
func NewDNSSECKeyFileNameFromString(path string) (DNSSECKeyFileName, error) {
	var result DNSSECKeyFileName

	if path == "" {
		return result, fmt.Errorf("cannot parse DNSSEC key file name: the name is empty")
	}

	// Drop any directory part, then any ".key" or ".private" suffix.  The
	// suffix rules are the ones dnssecKeyPairFileNames applies, so that a
	// name parsed here and a base name passed to ReadDNSSECKeyPair accept
	// exactly the same spellings.
	base := filepath.Base(path)
	switch ext := filepath.Ext(base); ext {
	case ".key", ".private":
		base = strings.TrimSuffix(base, ext)
	default:
		if strings.EqualFold(ext, ".key") || strings.EqualFold(ext, ".private") {
			return result, fmt.Errorf("cannot parse DNSSEC key file name %q: the key file suffix is %q, which is not spelled in lower case", path, ext)
		}
	}
	if base == "" {
		return result, fmt.Errorf("cannot parse DNSSEC key file name %q: the name is empty", path)
	}
	if !strings.HasPrefix(base, "K") {
		return result, fmt.Errorf("cannot parse DNSSEC key file name %q: the name does not begin with %q", path, "K")
	}

	// The owner name is not allowed to contain "+": the fields are split at
	// every "+" and a dnssec-keygen file name has exactly three of them.
	fields := strings.Split(base[1:], "+")
	if len(fields) != 3 {
		return result, fmt.Errorf("cannot parse DNSSEC key file name %q: after the %q prefix the name has %d fields separated by %q, want 3: the owner name, the algorithm and the key tag", path, "K", len(fields), "+")
	}

	name, err := NewDomainNameFromString(fields[0])
	if err != nil {
		return result, fmt.Errorf("cannot parse DNSSEC key file name %q: owner name %q: %w", path, fields[0], err)
	}
	algorithm, err := strconv.ParseUint(fields[1], 10, 8)
	if err != nil {
		return result, fmt.Errorf("cannot parse DNSSEC key file name %q: algorithm %q: %w", path, fields[1], err)
	}
	keyTag, err := strconv.ParseUint(fields[2], 10, 16)
	if err != nil {
		return result, fmt.Errorf("cannot parse DNSSEC key file name %q: key tag %q: %w", path, fields[2], err)
	}

	result.BaseName = base
	result.Name = name
	result.Algorithm = uint8(algorithm)
	result.KeyTag = uint16(keyTag)
	return result, nil
}

// NewDNSSECKeyBaseName returns the base name dnssec-keygen gives the two key
// files of a key: "K", the owner name in presentation format with its
// trailing dot, then "+" separated decimal fields for the algorithm and the
// key tag, zero-padded to 3 and 5 digits the way dnssec-keygen writes them.
// Appending ".key" or ".private" gives the two file names, and
// NewDNSSECKeyFileNameFromString parses the result back to the same owner
// name, algorithm and key tag.
func NewDNSSECKeyBaseName(name DomainName, algorithm uint8, keyTag uint16) string {
	return fmt.Sprintf("K%s+%03d+%05d", name.String(), algorithm, keyTag)
}

// InferDNSSECKeyNameFromFileName returns the DNSKEY owner name a
// dnssec-keygen key file name records: the key name is in the file name, so
// it is recoverable from the name of a ".private" file alone, which is the
// file whose contents carry no Name field (see ReadPrivateKeyFile).  This is
// a pure conversion over the file name and opens no file: the rules are the
// ones NewDNSSECKeyFileNameFromString applies, so the input spelling may be a
// full path or a bare file name, with or without a lower-case ".key" or
// ".private" suffix.  A file name that does not follow the
// "K<name>+<algorithm>+<key tag>" convention is an error that names the part
// of the name that caused it: the inferred name is the one the file name
// records, never a guess, and a caller that has an arbitrary file name
// supplies the owner name itself instead.
//
// The result is the same DomainName NewDNSSECKeyFileNameFromString returns in
// its Name field, which is also the owner name the same pair's ".key" file
// declares in its Name line.  Assign it to DNSSECKey.Name to complete a key
// read from a ".private" file, and MergeDNSSECKey can use it as the private
// half's name without losing the public half's: MergeDNSSECKey ignores the
// private half's Name, so a merged key can keep the name inferred from the
// ".private" file name.
//
// Inferring the name is not the same as completing the key: Name is not part
// of DNSKEY RDATA, so the key tag, the signer name of a signature made with
// the key, and the key's match against RecordRRSIG records all depend on it,
// and the public key material still comes only from the ".key" file.
func InferDNSSECKeyNameFromFileName(path string) (DomainName, error) {
	parsed, err := NewDNSSECKeyFileNameFromString(path)
	if err != nil {
		return DomainName{}, fmt.Errorf("cannot infer DNSSEC key name from %s: %w", path, err)
	}
	return parsed.Name, nil
}
