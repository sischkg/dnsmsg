package dnsmsg

import (
	"encoding/base64"
)

// encodeBase64 encodes bytes to a base64 string without padding (RFC 4634).
func encodeBase64(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// decodeBase64 decodes a base64 string without padding (RFC 4634).
func decodeBase64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
