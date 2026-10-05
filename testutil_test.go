package dnsmsg

import "testing"

// testDomainName constructs a DomainName from a presentation-format string
// for use in tests. It fails the test if the name cannot be parsed.
func testDomainName(t *testing.T, name string) DomainName {
	t.Helper()
	d, err := NewDomainNameFromString(name)
	if err != nil {
		t.Fatalf("testDomainName(%q): %v", name, err)
	}
	return d
}
