package identity

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const MaxSANs = 100
const MaxURIBytes = 2048

func DNS(value string, wildcard bool) error {
	original := value
	if wildcard {
		if !strings.HasPrefix(value, "*.") || strings.Count(value, "*") != 1 {
			return fmt.Errorf("wildcard must be like *.example.com: %s", original)
		}

		value = strings.TrimPrefix(value, "*.")
	} else if strings.Contains(value, "*") {
		return fmt.Errorf("use wildcard DNS for %s", value)
	}

	if len(value) > 253 || !strings.Contains(value, ".") {
		return fmt.Errorf("invalid DNS: %s", original)
	}

	for label := range strings.SplitSeq(value, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid DNS: %s", original)
		}

		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return fmt.Errorf("invalid DNS: %s", original)
			}
		}
	}

	return nil
}

func IP(value string) (net.IP, error) {
	v := net.ParseIP(value)
	if v == nil {
		return nil, fmt.Errorf("invalid IP SAN: %s", value)
	}

	return v, nil
}

func URI(value string) (*url.URL, error) {
	if len(value) > MaxURIBytes {
		return nil, errorsf("URI SAN exceeds %d bytes", MaxURIBytes)
	}

	u, e := url.ParseRequestURI(value)
	if e != nil || len(u.Scheme) == 0 {
		return nil, fmt.Errorf("invalid URI SAN: %s", value)
	}

	return u, nil
}

func SPIFFE(value string) (*url.URL, error) {
	id, e := spiffeid.FromString(value)
	if e != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", e)
	}

	return url.Parse(id.String())
}

func Count(total int) error {
	if total > MaxSANs {
		return fmt.Errorf("too many SANs: %d, maximum is %d", total, MaxSANs)
	}

	return nil
}

func errorsf(f string, a ...any) error { return fmt.Errorf(f, a...) }
