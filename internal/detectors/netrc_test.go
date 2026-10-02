package detectors

import "testing"

// DET-17: netrc_password matched the word after "password" anywhere in the
// file, including comments, at high confidence.
func TestNetrcPasswordIgnoresCommentsAndRequiresNetrcGrammar(t *testing.T) {
	set := Default()

	t.Run("comment line is not a password", func(t *testing.T) {
		content := "# password rotated quarterly\nmachine x login y password abc\n"
		for _, match := range set.Scan(ScanInput{Path: "/root/.netrc", Content: content}) {
			if match.Detector == "netrc_password" && match.Value == "rotated" {
				t.Fatalf("comment word reported as a password: %#v", match)
			}
		}
	})

	t.Run("password token on its own line is still found", func(t *testing.T) {
		content := "machine example.com\n  login deploy\n  password Sup3rS3cretPw\n"
		match, ok := findDetectorMatch(set.Scan(ScanInput{Path: "/root/.netrc", Content: content}), "netrc_password")
		if !ok || match.Value != "Sup3rS3cretPw" {
			t.Fatalf("match = %#v", match)
		}
	})

	t.Run("inline comment after the password is not part of it", func(t *testing.T) {
		content := "machine example.com login deploy password Sup3rS3cretPw # prod\n"
		match, ok := findDetectorMatch(set.Scan(ScanInput{Path: "/root/.netrc", Content: content}), "netrc_password")
		if !ok || match.Value != "Sup3rS3cretPw" {
			t.Fatalf("match = %#v", match)
		}
	})

	t.Run("prose containing the word password is not a credential", func(t *testing.T) {
		content := "# the password below is read by curl\n# never share your password with anyone\nmachine example.com login deploy password Sup3rS3cretPw\n"
		matches := set.Scan(ScanInput{Path: "/root/.netrc", Content: content})
		count := 0
		for _, match := range matches {
			if match.Detector == "netrc_password" {
				count++
				if match.Value != "Sup3rS3cretPw" {
					t.Fatalf("unexpected netrc_password value %q", match.Value)
				}
			}
		}
		if count != 1 {
			t.Fatalf("netrc_password count = %d: %#v", count, matches)
		}
	})
}
