package signature

import "strings"

// GroupFingerprint renders a fingerprint in four-character groups for
// human comparison (§6.5.2). It is presentation only, not validation.
func GroupFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := min(i+4, len(fp))
		b.WriteString(fp[i:end])
	}
	return b.String()
}
