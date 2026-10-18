package dnsmsg

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DNSSECKey is a DNSSEC key read from a dnssec-keygen key file.
//
// The .key file holds the public key material (flags, protocol, algorithm and
// public key) which corresponds to a DNSKEY record.  The .private file holds
// the private key material which is used to sign RRsets.
type DNSSECKey struct {
	// Name is the domain name the key is for (the owner name of the DNSKEY
	// record).
	Name DomainName
	// Flags are the DNSKEY flags (256 = zone key, 257 = secure entry point).
	Flags uint16
	// Protocol is the security protocol (always 3 for DNSSEC).
	Protocol uint8
	// Algorithm is the DNSSEC algorithm number (RFC 4034 Section 5.1.1).
	Algorithm uint8
	// PublicKey is the public key material.  It is populated when the key is
	// read from a .key file.
	PublicKey []byte
	// PrivateKey is the primary private key material.  It is populated when
	// the key is read from a .private file; its meaning depends on the
	// algorithm (for RSA it is the private exponent, for ECDSA it is the
	// private scalar).
	PrivateKey []byte
	// PrivateParams holds the named private key parameters parsed from a
	// .private file (for example "Modulus", "PrivateExponent", "PrivateKey").
	// It is nil when the key is read from a .key file.
	PrivateParams map[string][]byte
}

// ToDNSKEY converts the key into a RecordDNSKEY suitable for publishing in a
// zone file.  The private key material is not part of the DNSKEY record.
func (k *DNSSECKey) ToDNSKEY() RecordDNSKEY {
	return NewRecordDNSKEY(k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
}

// ReadKeyFile reads a dnssec-keygen .key file and returns the DNSSEC key it
// contains.  The file is expected to contain a DNSKEY record in zone file
// format, for example:
//
//	example.com. IN DNSKEY 256 3 5 <base64-public-key>
//
// Only the first DNSKEY record in the file is returned; comment and blank
// lines are skipped.
func ReadKeyFile(filename string) (*DNSSECKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file %s: %w", filename, err)
	}
	return parseKeyData(data, filename)
}

// ReadPrivateKeyFile reads a dnssec-keygen .private file and returns the
// DNSSEC key it contains.  The private key material and parameters are
// populated; the public key is not present in a .private file and is left nil.
func ReadPrivateKeyFile(filename string) (*DNSSECKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key file %s: %w", filename, err)
	}
	return parsePrivateKeyData(data, filename)
}

// parseKeyData parses the contents of a .key file.
func parseKeyData(data []byte, filename string) (*DNSSECKey, error) {
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip zone file directives such as $ORIGIN and $TTL.
		if strings.HasPrefix(line, "$") {
			continue
		}
		key, err := parseKeyLine(line)
		if err != nil {
			return nil, fmt.Errorf("cannot parse key file %s: %w", filename, err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("no DNSKEY record found in %s", filename)
}

// parseKeyLine parses a single DNSKEY record line from a .key file.
//
// Format: <name> IN DNSKEY <flags> <protocol> <algorithm> <base64-public-key>
func parseKeyLine(line string) (*DNSSECKey, error) {
	fields := strings.Fields(line)
	if len(fields) < 7 {
		return nil, fmt.Errorf("invalid DNSKEY key line %q: expected at least 7 fields", line)
	}
	if fields[1] != "IN" {
		return nil, fmt.Errorf("invalid DNSKEY key line %q: expected class IN", line)
	}
	if fields[2] != "DNSKEY" {
		return nil, fmt.Errorf("invalid DNSKEY key line %q: expected type DNSKEY", line)
	}

	name, err := NewDomainNameFromString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY name %q: %w", fields[0], err)
	}

	flags, err := strconvParseUint16(fields[3], "flags")
	if err != nil {
		return nil, err
	}

	protocol, err := strconvParseUint8(fields[4], "protocol")
	if err != nil {
		return nil, err
	}

	algorithm, err := strconvParseUint8(fields[5], "algorithm")
	if err != nil {
		return nil, err
	}

	publicKey, err := decodeBase64(fields[6])
	if err != nil {
		return nil, fmt.Errorf("invalid DNSKEY public key %q: %w", fields[6], err)
	}

	return &DNSSECKey{
		Name:      name,
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}, nil
}

// parsePrivateKeyData parses the contents of a dnssec-keygen .private file
// (Private-key-format v1.3).
func parsePrivateKeyData(data []byte, filename string) (*DNSSECKey, error) {
	key := &DNSSECKey{
		PrivateParams: make(map[string][]byte),
	}

	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		switch strings.ToLower(name) {
		case "private-key-format":
			// Informational only.
		case "algorithm":
			alg, err := parsePrivateAlgorithm(value)
			if err != nil {
				return nil, fmt.Errorf("cannot parse private key file %s: %w", filename, err)
			}
			key.Algorithm = alg
		case "created", "publish", "activate":
			// Timestamps are informational only.
		default:
			// Any other line is a named private key parameter carrying
			// base64-encoded material.
			decoded, err := decodeBase64(value)
			if err != nil {
				return nil, fmt.Errorf("cannot decode private key parameter %q in %s: %w", name, filename, err)
			}
			key.PrivateParams[name] = decoded
			if strings.EqualFold(name, "privatekey") || strings.EqualFold(name, "privateexponent") {
				key.PrivateKey = decoded
			}
		}
	}

	if key.Algorithm == 0 {
		return nil, fmt.Errorf("no algorithm found in private key file %s", filename)
	}
	return key, nil
}

// parsePrivateAlgorithm parses the "Algorithm: N (name)" line of a .private
// file and returns the algorithm number.
func parsePrivateAlgorithm(value string) (uint8, error) {
	// Value is like "5 (RSASHA1)" or just "5".
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return 0, fmt.Errorf("empty algorithm value %q", value)
	}
	alg, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid algorithm number %q: %w", parts[0], err)
	}
	return uint8(alg), nil
}

// strconvParseUint16 parses a decimal string into a uint16.
func strconvParseUint16(s, field string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, s, err)
	}
	return uint16(n), nil
}

// strconvParseUint8 parses a decimal string into a uint8.
func strconvParseUint8(s, field string) (uint8, error) {
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: %w", field, s, err)
	}
	return uint8(n), nil
}
