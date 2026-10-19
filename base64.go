package dnsmsg

import (
	"encoding/base64"
)

// encodeBase64 encodes bytes to a base64 string without padding (RFC 4634).
func encodeBase64(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// decodeBase64 decodes a base64 string, with or without padding.
//
// Unpadded material (RFC 4648 Section 3.2, as used in DNSSEC master files) is
// accepted, and so is the padded material written by dnssec-keygen key files.
func decodeBase64(s string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
