package limits

import (
	"errors"
	"fmt"
	"strings"
)

type Kind string

const (
	KindLayerBytes        Kind = "layer_bytes"
	KindLayerEntries      Kind = "layer_entries"
	KindManifestBytes     Kind = "manifest_bytes"
	KindConfigBytes       Kind = "config_bytes"
	KindRepositoryTags    Kind = "repository_tags"
	KindRepositoryTargets Kind = "repository_targets"
)

type ExceededError struct {
	Kind    Kind
	Limit   int64
	Subject string
}

func (e *ExceededError) Error() string {
	subject := strings.TrimSpace(e.Subject)
	if subject == "" {
		subject = "resource"
	}

	switch e.Kind {
	case KindLayerBytes:
		return fmt.Sprintf("%s exceeded max layer bytes limit of %d", subject, e.Limit)
	case KindLayerEntries:
		return fmt.Sprintf("%s exceeded max layer entries limit of %d", subject, e.Limit)
	case KindManifestBytes:
		return fmt.Sprintf("%s exceeded max manifest bytes limit of %d", subject, e.Limit)
	case KindConfigBytes:
		return fmt.Sprintf("%s exceeded max config bytes limit of %d", subject, e.Limit)
	case KindRepositoryTags:
		return fmt.Sprintf("%s exceeded max repository tags limit of %d", subject, e.Limit)
	case KindRepositoryTargets:
		return fmt.Sprintf("%s exceeded max repository targets limit of %d", subject, e.Limit)
	default:
		return fmt.Sprintf("%s exceeded configured limit of %d", subject, e.Limit)
	}
}

func NewExceeded(kind Kind, limit int64, subject string) error {
	return &ExceededError{
		Kind:    kind,
		Limit:   limit,
		Subject: subject,
	}
}

func IsExceeded(err error) bool {
	var target *ExceededError
	return errors.As(err, &target)
}

func AsExceeded(err error) (*ExceededError, bool) {
	var target *ExceededError
	if !errors.As(err, &target) {
		return nil, false
	}

	return target, true
}
