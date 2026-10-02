package manifest

import (
	"fmt"
	"strings"
)

// SkipReason classifies an index entry that was not selected for scanning.
// The values double as diagnostic codes.
type SkipReason string

const (
	// SkipReasonUnsupportedManifest marks entries that are not scannable image
	// manifests: attestation manifests, nested indexes, artifact descriptors and
	// other non-image media types.
	SkipReasonUnsupportedManifest SkipReason = "manifest_skipped"
	// SkipReasonPlatform marks image manifests left out by the default
	// linux-only platform policy.
	SkipReasonPlatform SkipReason = "platform_skipped"
)

// SkippedDescriptor records why an index entry was not selected.
type SkippedDescriptor struct {
	Descriptor Descriptor
	Reason     SkipReason
	Detail     string
}

// Selection is the outcome of applying the platform policy to an image index.
type Selection struct {
	Selected []Descriptor
	Skipped  []SkippedDescriptor
}

// SelectManifests applies the platform policy to an image index.
//
// Without a selector every scannable image manifest whose platform OS is
// linux (or unspecified) is selected; non-image entries and manifests for
// other operating systems are reported in Skipped. With a selector only the
// matching image manifests are selected; entries that do not match the
// selector are left out silently and non-image entries that would otherwise
// match are reported.
func SelectManifests(index ImageIndex, selector string) (Selection, error) {
	explicit := strings.TrimSpace(selector) != ""
	var want Platform
	if explicit {
		parsed, err := ParsePlatformSelector(selector)
		if err != nil {
			return Selection{}, err
		}
		want = parsed
	}

	selection := Selection{
		Selected: make([]Descriptor, 0, len(index.Manifests)),
		Skipped:  make([]SkippedDescriptor, 0),
	}
	scannable := 0
	for _, candidate := range index.Manifests {
		if selection.consider(candidate, explicit, want) {
			scannable++
		}
	}

	if len(selection.Selected) == 0 {
		return Selection{}, emptySelectionError(scannable, explicit, want)
	}

	unique, err := uniqueDescriptors(selection.Selected)
	if err != nil {
		return Selection{}, err
	}
	selection.Selected = unique
	return selection, nil
}

// consider applies the platform policy to one index entry, appending it to
// Selected or Skipped, and reports whether it is a scannable image manifest.
func (s *Selection) consider(candidate Descriptor, explicit bool, want Platform) bool {
	if detail, ok := unsupportedIndexEntryDetail(candidate); ok {
		if !explicit || candidate.Platform.Matches(want) {
			s.skip(candidate, SkipReasonUnsupportedManifest, detail)
		}
		return false
	}
	switch {
	case explicit:
		if candidate.Platform.Matches(want) {
			s.Selected = append(s.Selected, candidate)
		}
	case isDefaultPlatform(candidate.Platform):
		s.Selected = append(s.Selected, candidate)
	default:
		s.skip(candidate, SkipReasonPlatform, fmt.Sprintf("skipped platform %s: only %s manifests are selected without a platform selector", candidate.Platform.String(), DefaultPlatformOS))
	}
	return true
}

func (s *Selection) skip(descriptor Descriptor, reason SkipReason, detail string) {
	s.Skipped = append(s.Skipped, SkippedDescriptor{Descriptor: descriptor, Reason: reason, Detail: detail})
}

// emptySelectionError explains why no image manifest was selected.
func emptySelectionError(scannable int, explicit bool, want Platform) error {
	switch {
	case scannable == 0:
		return fmt.Errorf("image index does not contain supported image manifests")
	case explicit:
		return fmt.Errorf("platform %s not found in manifest index", want.String())
	default:
		return fmt.Errorf("image index does not contain %s image manifests; select another platform explicitly", DefaultPlatformOS)
	}
}

// SelectDescriptors returns only the selected descriptors of SelectManifests.
func SelectDescriptors(index ImageIndex, selector string) ([]Descriptor, error) {
	selection, err := SelectManifests(index, selector)
	if err != nil {
		return nil, err
	}
	return selection.Selected, nil
}

func unsupportedIndexEntryDetail(descriptor Descriptor) (string, bool) {
	switch {
	case IsIndexMediaType(descriptor.MediaType):
		return "skipped index entry: nested image indexes are not scanned", true
	case !IsManifestMediaType(descriptor.MediaType):
		return fmt.Sprintf("skipped index entry: media type %q is not an image manifest", MediaTypeBase(descriptor.MediaType)), true
	case IsAttestationDescriptor(descriptor):
		return "skipped attestation manifest", true
	default:
		return "", false
	}
}

func isDefaultPlatform(platform Platform) bool {
	os := strings.ToLower(strings.TrimSpace(platform.OS))
	return os == "" || os == DefaultPlatformOS
}

func uniqueDescriptors(items []Descriptor) ([]Descriptor, error) {
	selected := make([]Descriptor, 0, len(items))
	seen := make(map[string]Descriptor, len(items))
	for _, item := range items {
		if previous, ok := seen[item.Digest]; ok {
			if previous.MediaType != item.MediaType || previous.Size != item.Size || previous.Platform != item.Platform {
				return nil, &IntegrityError{
					Kind:     IntegrityInvalidDocument,
					Subject:  item.Digest,
					Expected: "one consistent descriptor per digest",
					Actual:   "conflicting descriptors",
				}
			}
			continue
		}
		seen[item.Digest] = item
		selected = append(selected, item)
	}
	return selected, nil
}
