package layers

import "strings"

// undoKind names one reversible mutation of the final map or directory set.
type undoKind uint8

const (
	// undoFinalSet: final[path] was set; prev/hadPrev hold the earlier value.
	undoFinalSet undoKind = iota
	// undoFinalDelete: final[path] was deleted; prev holds the earlier value.
	undoFinalDelete
	// undoDirAdd: dirs[path] was added.
	undoDirAdd
	// undoDirRemove: dirs[path] was removed.
	undoDirRemove
)

// undoRecord is kept small (a pointer rather than an embedded Artifact) so a
// layer of many directory entries journals a few dozen bytes per entry; the
// previous artifact is only allocated for the two kinds that need it.
type undoRecord struct {
	kind undoKind
	path string
	prev *Artifact
}

// layerJournal makes one layer's mutations transactional without copying the
// state. Every change to final, dirs and the path indexes is recorded as its
// inverse while the layer is applied; on failure the records are replayed
// backwards, the deleted list is truncated and the retained-byte counter is
// restored, so the state is exactly what it was before the layer (LAY-14).
// Its cost is proportional to the entries of the layer, not to the size of
// the image.
//
// The journal also remembers which paths the layer itself created so the
// whiteout pass at the end of the layer can tell lower-layer entries (the only
// ones a whiteout removes) from this layer's own, without a snapshot of the
// lower state.
type layerJournal struct {
	records       []undoRecord
	deletedLength int
	coverage      Coverage
	// currentPaths holds every entry path this layer recorded.
	currentPaths map[string]struct{}
	// createdDirs holds the directories this layer added (and has not removed
	// since). A base directory removed and re-added by this layer is counted
	// as created: everything below it was already deleted by the removal.
	createdDirs map[string]struct{}
}

// beginLayer starts journaling mutations of s until endLayer or rollback.
func (s *State) beginLayer() *layerJournal {
	journal := &layerJournal{
		deletedLength: len(s.deleted),
		coverage:      s.coverage,
		currentPaths:  make(map[string]struct{}),
		createdDirs:   make(map[string]struct{}),
	}
	s.journal = journal
	return journal
}

// endLayer commits the layer: the journal is dropped.
func (s *State) endLayer() {
	s.journal = nil
}

func (j *layerJournal) record(item undoRecord) {
	if j == nil {
		return
	}
	j.records = append(j.records, item)
}

func (j *layerJournal) ownsPath(target string) bool {
	if j == nil {
		return false
	}
	_, ok := j.currentPaths[target]
	return ok
}

func (j *layerJournal) createdDir(target string) bool {
	if j == nil {
		return false
	}
	_, ok := j.createdDirs[target]
	return ok
}

// rollback undoes every recorded mutation in reverse order and restores the
// deleted list and retained-byte counter to their pre-layer values. The other
// coverage counters are observations of the failed layer and are kept by the
// caller.
func (s *State) rollback(journal *layerJournal) {
	for index := len(journal.records) - 1; index >= 0; index-- {
		item := journal.records[index]
		switch item.kind {
		case undoFinalSet:
			if item.prev != nil {
				s.final[item.path] = *item.prev
			} else {
				delete(s.final, item.path)
				removePathIndexEntry(s.artifactChildren, item.path)
			}
		case undoFinalDelete:
			s.final[item.path] = *item.prev
			addPathIndexEntry(s.artifactChildren, item.path)
		case undoDirAdd:
			delete(s.dirs, item.path)
			removePathIndexEntry(s.directoryChildren, item.path)
		case undoDirRemove:
			s.dirs[item.path] = struct{}{}
			addPathIndexEntry(s.directoryChildren, item.path)
		}
	}
	for index := journal.deletedLength; index < len(s.deleted); index++ {
		s.deleted[index] = Artifact{}
	}
	s.deleted = s.deleted[:journal.deletedLength]
	s.coverage.RetainedBytes = journal.coverage.RetainedBytes
	s.journal = nil
}

// setFinal records and applies final[artifact.Path] = artifact.
func (s *State) setFinal(artifact Artifact) {
	if s.journal != nil {
		item := undoRecord{kind: undoFinalSet, path: artifact.Path}
		if prev, hadPrev := s.final[artifact.Path]; hadPrev {
			item.prev = &prev
		}
		s.journal.record(item)
	}
	s.final[artifact.Path] = artifact
	addPathIndexEntry(s.artifactChildren, artifact.Path)
}

// unsetFinal records and applies delete(final, path); the caller has checked
// that the path exists.
func (s *State) unsetFinal(targetPath string, current Artifact) {
	if s.journal != nil {
		s.journal.record(undoRecord{kind: undoFinalDelete, path: targetPath, prev: &current})
	}
	delete(s.final, targetPath)
	removePathIndexEntry(s.artifactChildren, targetPath)
}

// deleteLowerPath applies a whiteout: the lower-layer artifact at target, and
// everything below it when target is a lower-layer directory, is deleted.
// Entries this layer recorded itself are untouched, as the OCI image spec
// requires.
func (s *State) deleteLowerPath(target, deletedBy string, journal *layerJournal) {
	if !journal.ownsPath(target) {
		if _, ok := s.final[target]; ok {
			s.deletePath(target, deletedBy)
		}
	}
	if _, ok := s.dirs[target]; ok && !journal.createdDir(target) {
		s.deleteLowerPrefix(target, deletedBy, journal)
	}
}

// deleteLowerPrefix applies an opaque whiteout (or a whiteout of a directory):
// every lower-layer artifact below directory is deleted and every lower-layer
// directory at or below it that is left empty is removed, deepest first.
func (s *State) deleteLowerPrefix(directory, deletedBy string, journal *layerJournal) {
	directory = strings.Trim(directory, "/")
	for _, target := range s.artifactPathsBelow(directory) {
		if journal.ownsPath(target) {
			continue
		}
		s.deletePath(target, deletedBy)
	}
	for _, target := range s.directoryPathsAtOrBelow(directory) {
		if journal.ownsPath(target) || journal.createdDir(target) {
			continue
		}
		s.removeDirectory(target)
	}
}
