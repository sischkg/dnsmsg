package dnsmsg

import (
	"bytes"
	"testing"
	"time"
)

// fixedTime is used so TSIG signatures are deterministic in tests.
var fixedTime = time.Unix(1700000000, 0).UTC()

func testTSIGKey(t *testing.T, algorithm TSIGAlgorithm) TSIGKey {
	t.Helper()
	key, err := NewTSIGKeyFromString("tsig-key.example.", string(algorithm), "aaaa")
	if err != nil {
		t.Fatalf("NewTSIGKeyFromString() error = %v", err)
	}
	return key
}

func testQueryMessage(t *testing.T) Message {
	t.Helper()
	msg := Message{
		ID:      0xC0DE,
		QR:      QRQuery,
		QDCOUNT: 1,
		QuestionSection: []QuestionSectionEntry{
			{QName: testDomainName(t, "example.com."), Class: CLASS_IN, Type: TYPE_A},
		},
	}
	if err := msg.checkSectionCounts(); err != nil {
		t.Fatalf("checkSectionCounts() error = %v", err)
	}
	return msg
}

// appendTSIGAndWrite appends the TSIG record to the additional section,
// raises ARCOUNT, and serializes the message to wire format.
func appendTSIGAndWrite(t *testing.T, msg Message, rr ResourceRecord) WireFormat {
	t.Helper()
	msg.AdditionalSection = append(msg.AdditionalSection, rr)
	msg.ARCOUNT++
	if err := msg.checkSectionCounts(); err != nil {
		t.Fatalf("checkSectionCounts() error = %v", err)
	}
	var w WireFormat
	w.WriteWireFormat(msg)
	return w
}

func TestSignTSIGQueryVerifyRoundTrip(t *testing.T) {
	key := testTSIGKey(t, TSIGAlgHMACSHA256)
	msg := testQueryMessage(t)

	rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
	if err != nil {
		t.Fatalf("SignTSIG() error = %v", err)
	}

	tsig, ok := rr.RData.(RecordTSIG)
	if !ok {
		t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
	}
	if !rr.Name.Equal(key.Name) {
		t.Errorf("RR name = %v, want %v", rr.Name, key.Name)
	}
	if rr.Class != CLASS_ANY {
		t.Errorf("RR class = %v, want CLASS_ANY", rr.Class)
	}
	if rr.TTL != 0 {
		t.Errorf("RR TTL = %d, want 0", rr.TTL)
	}
	if tsig.OriginalID != msg.ID {
		t.Errorf("OriginalID = %d, want %d", tsig.OriginalID, msg.ID)
	}
	if tsig.TimeSigned != uint64(fixedTime.Unix()) {
		t.Errorf("TimeSigned = %d, want %d", tsig.TimeSigned, fixedTime.Unix())
	}
	if tsig.Error != TSIGErrorNoError {
		t.Errorf("Error = %v, want TSIGErrorNoError", tsig.Error)
	}
	if len(tsig.MAC) == 0 {
		t.Error("MAC is empty")
	}
	if len(tsig.MAC) > key.Algorithm.MACLen() {
		t.Errorf("MAC length = %d, want <= %d", len(tsig.MAC), key.Algorithm.MACLen())
	}

	w := appendTSIGAndWrite(t, msg, rr)

	if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: fixedTime}); err != nil {
		t.Fatalf("VerifyTSIG() error = %v", err)
	}

	// The TSIG record must parse back out of the wire format.
	parsed, err := ParseWireFormat(w)
	if err != nil {
		t.Fatalf("ParseWireFormat() error = %v", err)
	}
	if parsed.ARCOUNT != 1 {
		t.Errorf("ARCOUNT = %d, want 1", parsed.ARCOUNT)
	}
	if len(parsed.AdditionalSection) != 1 {
		t.Errorf("AdditionalSection = %d records, want 1", len(parsed.AdditionalSection))
	}
	gotTSIG, ok := parsed.AdditionalSection[0].RData.(RecordTSIG)
	if !ok {
		t.Fatalf("AdditionalSection[0].RData = %T, want RecordTSIG", parsed.AdditionalSection[0].RData)
	}
	if !bytes.Equal(gotTSIG.MAC, tsig.MAC) {
		t.Errorf("parsed MAC = %v, want %v", gotTSIG.MAC, tsig.MAC)
	}
	if !gotTSIG.Algorithm.Equal(tsig.Algorithm) {
		t.Errorf("parsed Algorithm = %v, want %v", gotTSIG.Algorithm, tsig.Algorithm)
	}
	if gotTSIG.TimeSigned != tsig.TimeSigned {
		t.Errorf("parsed TimeSigned = %d, want %d", gotTSIG.TimeSigned, tsig.TimeSigned)
	}
	if gotTSIG.Fudge != tsig.Fudge {
		t.Errorf("parsed Fudge = %d, want %d", gotTSIG.Fudge, tsig.Fudge)
	}
	if gotTSIG.OriginalID != tsig.OriginalID {
		t.Errorf("parsed OriginalID = %d, want %d", gotTSIG.OriginalID, tsig.OriginalID)
	}
	if gotTSIG.Error != tsig.Error {
		t.Errorf("parsed Error = %v, want %v", gotTSIG.Error, tsig.Error)
	}
	// OtherData is nil in the signed record but an empty slice after a
	// round trip through the wire, so compare lengths only.
	if len(gotTSIG.OtherData) != len(tsig.OtherData) {
		t.Errorf("parsed OtherData length = %d, want %d", len(gotTSIG.OtherData), len(tsig.OtherData))
	}
}

func TestSignTSIGResponseVerifyRoundTrip(t *testing.T) {
	key := testTSIGKey(t, TSIGAlgHMACSHA256)

	// Sign the request.
	request := testQueryMessage(t)
	requestRR, err := request.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
	if err != nil {
		t.Fatalf("SignTSIG(request) error = %v", err)
	}
	requestTSIG, ok := requestRR.RData.(RecordTSIG)
	if !ok {
		t.Fatalf("RData = %T, want RecordTSIG", requestRR.RData)
	}
	requestWire := appendTSIGAndWrite(t, request, requestRR)

	// Sign the response, authenticating the request's MAC.
	response := Message{
		ID:      request.ID,
		QR:      QRResponse,
		RA:      1,
		QDCOUNT: 1,
		QuestionSection: []QuestionSectionEntry{
			{QName: testDomainName(t, "example.com."), Class: CLASS_IN, Type: TYPE_A},
		},
		ANCOUNT: 1,
		AnswerSection: []ResourceRecord{
			{
				Name:  testDomainName(t, "example.com."),
				Class: CLASS_IN,
				Type:  TYPE_A,
				TTL:   3600,
				RData: NewRecordA([4]byte{192, 0, 2, 1}),
			},
		},
	}
	if err := response.checkSectionCounts(); err != nil {
		t.Fatalf("checkSectionCounts() error = %v", err)
	}
	responseRR, err := response.SignTSIG(key, &TSIGOptions{
		TimeSigned: fixedTime,
		RequestMAC: requestTSIG.MAC,
	})
	if err != nil {
		t.Fatalf("SignTSIG(response) error = %v", err)
	}
	responseWire := appendTSIGAndWrite(t, response, responseRR)

	if err := VerifyTSIG(responseWire, key, &TSIGVerifyOptions{
		RequestMAC: requestTSIG.MAC,
		Now:        fixedTime,
	}); err != nil {
		t.Fatalf("VerifyTSIG(response) error = %v", err)
	}

	// The request's TSIG record must also verify on its own.
	if err := VerifyTSIG(requestWire, key, &TSIGVerifyOptions{Now: fixedTime}); err != nil {
		t.Fatalf("VerifyTSIG(request) error = %v", err)
	}
}

func TestSignTSIGAllAlgorithms(t *testing.T) {
	algorithms := []TSIGAlgorithm{
		TSIGAlgHMACMD5,
		TSIGAlgHMACSHA1,
		TSIGAlgHMACSHA224,
		TSIGAlgHMACSHA256,
		TSIGAlgHMACSHA256_128,
		TSIGAlgHMACSHA384,
		TSIGAlgHMACSHA384_192,
		TSIGAlgHMACSHA512,
		TSIGAlgHMACSHA512_256,
	}
	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			key := testTSIGKey(t, algorithm)
			// 短縮アルゴリズム（hmac-sha256-128 など）では MAC 長を
			// アルゴリズムが許容する最大値に明示的に設定する。
			key.MACLen = key.Algorithm.MACLen()
			msg := testQueryMessage(t)

			rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
			if err != nil {
				t.Fatalf("SignTSIG() error = %v", err)
			}
			tsig, ok := rr.RData.(RecordTSIG)
			if !ok {
				t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
			}
			if !tsig.Algorithm.Equal(key.Algorithm.DomainName()) {
				t.Errorf("Algorithm = %v, want %v", tsig.Algorithm, key.Algorithm.DomainName())
			}
			if len(tsig.MAC) == 0 {
				t.Error("MAC is empty")
			}
			if len(tsig.MAC) > key.Algorithm.MACLen() {
				t.Errorf("MAC length = %d, want <= %d", len(tsig.MAC), key.Algorithm.MACLen())
			}

			w := appendTSIGAndWrite(t, msg, rr)
			if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: fixedTime}); err != nil {
				t.Fatalf("VerifyTSIG() error = %v", err)
			}
		})
	}
}

func TestSignTSIGErrors(t *testing.T) {
	key := testTSIGKey(t, TSIGAlgHMACSHA256)

	t.Run("message already has a TSIG record", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.ARCOUNT++

		if _, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime}); err == nil {
			t.Error("SignTSIG() error = nil, want an error for a message that already has a TSIG record")
		}
	})

	t.Run("section counts do not match", func(t *testing.T) {
		msg := testQueryMessage(t)
		msg.QDCOUNT = 2 // lie about the count

		if _, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime}); err == nil {
			t.Error("SignTSIG() error = nil, want an error for mismatched section counts")
		}
	})
}

func TestSignTSIGInvalidKey(t *testing.T) {
	msg := testQueryMessage(t)

	// Empty secret.
	key, err := NewTSIGKey(testDomainName(t, "tsig-key.example."), TSIGAlgHMACSHA256, nil)
	if err == nil {
		t.Error("NewTSIGKey() error = nil, want an error for an empty secret")
	} else {
		_ = key
	}
	if _, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime}); err == nil {
		t.Error("SignTSIG() error = nil, want an error for an invalid key")
	}
}

func TestVerifyTSIGErrors(t *testing.T) {
	key := testTSIGKey(t, TSIGAlgHMACSHA256)

	t.Run("no TSIG record", func(t *testing.T) {
		msg := testQueryMessage(t)
		var w WireFormat
		w.WriteWireFormat(msg)
		if err := VerifyTSIG(w, key, nil); err == nil {
			t.Error("VerifyTSIG() error = nil, want an error for a message without a TSIG record")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherKey := testTSIGKey(t, TSIGAlgHMACSHA256)
		// A different secret for the same key name.
		otherKey.Secret = []byte("different-secret")

		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		w := appendTSIGAndWrite(t, msg, rr)

		if err := VerifyTSIG(w, otherKey, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("VerifyTSIG() error = nil, want an error for the wrong key")
		}
	})

	t.Run("tampered MAC", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		tsig, ok := rr.RData.(RecordTSIG)
		if !ok {
			t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
		}
		// Flip a bit in the MAC.
		tsig.MAC[0] ^= 0xFF
		rr.RData = tsig

		w := appendTSIGAndWrite(t, msg, rr)
		if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("VerifyTSIG() error = nil, want an error for a tampered MAC")
		}
	})

	t.Run("bad time", func(t *testing.T) {
		msg := testQueryMessage(t)
		// Sign far in the past so the current time is outside the fudge window.
		longAgo := time.Unix(0, 0).UTC()
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: longAgo, Fudge: 1})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		w := appendTSIGAndWrite(t, msg, rr)

		if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("VerifyTSIG() error = nil, want a BADTIME error for an out-of-window signature")
		}
	})

	t.Run("bad algorithm", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		tsig, ok := rr.RData.(RecordTSIG)
		if !ok {
			t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
		}
		// Change the algorithm name to one the key does not use.
		tsig.Algorithm = testDomainName(t, "hmac-sha1.")
		rr.RData = tsig

		w := appendTSIGAndWrite(t, msg, rr)
		if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("VerifyTSIG() error = nil, want a BADKEY error for the wrong algorithm")
		}
	})

	t.Run("verify within fudge window", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime, Fudge: 300})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		w := appendTSIGAndWrite(t, msg, rr)

		// One second before and one second after the signed time should both pass.
		for _, now := range []time.Time{
			fixedTime.Add(-1 * time.Second),
			fixedTime,
			fixedTime.Add(1 * time.Second),
		} {
			if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: now}); err != nil {
				t.Errorf("VerifyTSIG() error = %v, want nil at %s", err, now)
			}
		}
	})
}

func TestSignTSIGCustomOptions(t *testing.T) {
	key := testTSIGKey(t, TSIGAlgHMACSHA256)
	msg := testQueryMessage(t)

	rr, err := msg.SignTSIG(key, &TSIGOptions{
		TimeSigned: fixedTime,
		Fudge:      60,
		Error:      TSIGErrorNoError,
		OtherData:  []byte{0xDE, 0xAD, 0xBE, 0xEF},
	})
	if err != nil {
		t.Fatalf("SignTSIG() error = %v", err)
	}
	tsig, ok := rr.RData.(RecordTSIG)
	if !ok {
		t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
	}
	if tsig.Fudge != 60 {
		t.Errorf("Fudge = %d, want 60", tsig.Fudge)
	}
	if !bytes.Equal(tsig.OtherData, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("OtherData = %v, want [0xDE 0xAD 0xBE 0xEF]", tsig.OtherData)
	}

	w := appendTSIGAndWrite(t, msg, rr)
	if err := VerifyTSIG(w, key, &TSIGVerifyOptions{Now: fixedTime}); err != nil {
		t.Fatalf("VerifyTSIG() error = %v", err)
	}
}

func TestMessageVerifyTSIG(t *testing.T) {
	key := testTSIGKey(t, TSIGAlgHMACSHA256)

	t.Run("valid signed message verifies", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.ARCOUNT++

		if err := msg.VerifyTSIG(key, &TSIGVerifyOptions{Now: fixedTime}); err != nil {
			t.Fatalf("Message.VerifyTSIG() error = %v", err)
		}
	})

	t.Run("valid response with RequestMAC verifies", func(t *testing.T) {
		request := testQueryMessage(t)
		requestRR, err := request.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG(request) error = %v", err)
		}
		requestTSIG, ok := requestRR.RData.(RecordTSIG)
		if !ok {
			t.Fatalf("RData = %T, want RecordTSIG", requestRR.RData)
		}

		response := Message{
			ID:      request.ID,
			QR:      QRResponse,
			RA:      1,
			QDCOUNT: 1,
			QuestionSection: []QuestionSectionEntry{
				{QName: testDomainName(t, "example.com."), Class: CLASS_IN, Type: TYPE_A},
			},
			ANCOUNT: 1,
			AnswerSection: []ResourceRecord{
				{
					Name:  testDomainName(t, "example.com."),
					Class: CLASS_IN,
					Type:  TYPE_A,
					TTL:   3600,
					RData: NewRecordA([4]byte{192, 0, 2, 1}),
				},
			},
		}
		if err := response.checkSectionCounts(); err != nil {
			t.Fatalf("checkSectionCounts() error = %v", err)
		}
		responseRR, err := response.SignTSIG(key, &TSIGOptions{
			TimeSigned: fixedTime,
			RequestMAC: requestTSIG.MAC,
		})
		if err != nil {
			t.Fatalf("SignTSIG(response) error = %v", err)
		}
		response.AdditionalSection = append(response.AdditionalSection, responseRR)
		response.ARCOUNT++

		if err := response.VerifyTSIG(key, &TSIGVerifyOptions{
			RequestMAC: requestTSIG.MAC,
			Now:        fixedTime,
		}); err != nil {
			t.Fatalf("Message.VerifyTSIG(response) error = %v", err)
		}
	})

	t.Run("no TSIG record", func(t *testing.T) {
		msg := testQueryMessage(t)
		if err := msg.VerifyTSIG(key, nil); err == nil {
			t.Error("Message.VerifyTSIG() error = nil, want an error for a message without a TSIG record")
		}
	})

	t.Run("TSIG record not last in additional section", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		// Add a non-TSIG record after the TSIG record.
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.AdditionalSection = append(msg.AdditionalSection, ResourceRecord{
			Name:  testDomainName(t, "example.com."),
			Class: CLASS_IN,
			Type:  TYPE_A,
			TTL:   3600,
			RData: NewRecordA([4]byte{192, 0, 2, 1}),
		})
		msg.ARCOUNT = 2

		if err := msg.VerifyTSIG(key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("Message.VerifyTSIG() error = nil, want an error when TSIG is not last")
		}
	})

	t.Run("multiple TSIG records", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.ARCOUNT = 2

		if err := msg.VerifyTSIG(key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("Message.VerifyTSIG() error = nil, want an error for multiple TSIG records")
		}
	})

	t.Run("tampered MAC", func(t *testing.T) {
		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		tsig, ok := rr.RData.(RecordTSIG)
		if !ok {
			t.Fatalf("RData = %T, want RecordTSIG", rr.RData)
		}
		tsig.MAC[0] ^= 0xFF
		rr.RData = tsig
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.ARCOUNT++

		if err := msg.VerifyTSIG(key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("Message.VerifyTSIG() error = nil, want an error for a tampered MAC")
		}
	})

	t.Run("bad time", func(t *testing.T) {
		msg := testQueryMessage(t)
		longAgo := time.Unix(0, 0).UTC()
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: longAgo, Fudge: 1})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.ARCOUNT++

		if err := msg.VerifyTSIG(key, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("Message.VerifyTSIG() error = nil, want a BADTIME error for an out-of-window signature")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		otherKey := testTSIGKey(t, TSIGAlgHMACSHA256)
		otherKey.Secret = []byte("different-secret")

		msg := testQueryMessage(t)
		rr, err := msg.SignTSIG(key, &TSIGOptions{TimeSigned: fixedTime})
		if err != nil {
			t.Fatalf("SignTSIG() error = %v", err)
		}
		msg.AdditionalSection = append(msg.AdditionalSection, rr)
		msg.ARCOUNT++

		if err := msg.VerifyTSIG(otherKey, &TSIGVerifyOptions{Now: fixedTime}); err == nil {
			t.Error("Message.VerifyTSIG() error = nil, want an error for the wrong key")
		}
	})
}
