package dnsmsg

import (
	"fmt"
	"io"
	"strings"
)

// These functions parse dnssec-keygen key contents from a byte slice or an
// io.Reader instead of a file path.  They apply exactly the rules
// ReadKeyFile and ReadPrivateKeyFile apply to file contents — the same
// accepted formats, the same fields populated, the same errors for malformed
// input — but they never touch the filesystem.  ReadKeyFile and
// ReadPrivateKeyFile are file reading plus these parse rules; a caller that
// has already obtained the contents by some other means (an embedded resource,
// a configuration store, a test fixture) should call these instead.
//
// The source labels in their error messages name the input the caller passed
// ("DNSSEC key data", or the label given to ParseDNSSECKeyWithSource /
// ParseDNSSECPrivateKeyWithSource) instead of a file path.
//
// Default labels naming the input of the label-free functions.
const (
	dnssecKeyDataLabel        = "DNSSEC key data"
	dnssecPrivateKeyDataLabel = "DNSSEC private key data"
)

// ParseDNSSECKey parses the contents of a dnssec-keygen .key file from a byte
// slice and returns the DNSSEC key it contains.  The contents are expected to
// include a DNSKEY record in zone file format, for example:
//
//	example.com. IN DNSKEY 256 3 5 <base64-public-key>
//
// Only the first DNSKEY record in the data is returned; comment and blank
// lines and zone file directives are skipped.  This is the parse of
// ReadKeyFile without the file read; empty or DNSKEY-free data is an error,
// never a nil key without one.
func ParseDNSSECKey(data []byte) (*DNSSECKey, error) {
	return ParseDNSSECKeyWithSource(data, "")
}

// ParseDNSSECKeyWithSource parses .key contents like ParseDNSSECKey and uses
// source to name the data in error messages, for a caller whose data came
// from a source it can describe ("Kexample.com.+008+24861 embedded in
// config").  An empty source names the data "DNSSEC key data", as
// ParseDNSSECKey does.
func ParseDNSSECKeyWithSource(data []byte, source string) (*DNSSECKey, error) {
	if source == "" {
		source = dnssecKeyDataLabel
	}
	return parseKeyData(data, source, source)
}

// ParseDNSSECPrivateKey parses the contents of a dnssec-keygen .private file
// (Private-key-format v1.3) from a byte slice and returns the DNSSEC key it
// contains.  The private key material and parameters are populated; the public
// key is not present in a .private file and is left nil.  This is the parse
// of ReadPrivateKeyFile without the file read: like it, a .private file that
// carries a "Name:" line is rejected, because a lone private key has nothing
// to take the owner name from.  Empty or algorithm-free data is an error,
// never a nil key without one.
func ParseDNSSECPrivateKey(data []byte) (*DNSSECKey, error) {
	return ParseDNSSECPrivateKeyWithSource(data, "")
}

// ParseDNSSECPrivateKeyWithSource parses .private contents like
// ParseDNSSECPrivateKey and uses source to name the data in error messages.
// An empty source names the data "DNSSEC private key data", as
// ParseDNSSECPrivateKey does.
func ParseDNSSECPrivateKeyWithSource(data []byte, source string) (*DNSSECKey, error) {
	if source == "" {
		source = dnssecPrivateKeyDataLabel
	}
	return parsePrivateKeyData(data, source, source)
}

// ParseDNSSECKeyLine parses a single DNSKEY record line of the form
//
//	<name> IN DNSKEY <flags> <protocol> <algorithm> <base64-public-key>
//
// which is what a .key file's DNSKEY line is.  Leading and trailing
// whitespace is ignored; the error messages are those of the line parser
// ParseDNSSECKey uses per line ("invalid DNSKEY key line ...").
func ParseDNSSECKeyLine(line string) (*DNSSECKey, error) {
	return parseKeyLine(strings.TrimSpace(line))
}

// ReadDNSSECKey reads all of r and parses the result as .key contents, the
// same way ParseDNSSECKey does.  It reads the reader once, to the end, and a
// read failure is reported as "cannot read DNSSEC key data: ...".  It never
// touches the filesystem: a file remains ReadKeyFile's job.
func ReadDNSSECKey(r io.Reader) (*DNSSECKey, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", dnssecKeyDataLabel, err)
	}
	return ParseDNSSECKey(data)
}

// ReadDNSSECPrivateKey reads all of r and parses the result as .private
// contents, the same way ParseDNSSECPrivateKey does.  A read failure is
// reported as "cannot read DNSSEC private key data: ...".
func ReadDNSSECPrivateKey(r io.Reader) (*DNSSECKey, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", dnssecPrivateKeyDataLabel, err)
	}
	return ParseDNSSECPrivateKey(data)
}
