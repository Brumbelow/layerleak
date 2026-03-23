ALTER TABLE finding_occurrences
    ADD COLUMN disposition TEXT NOT NULL DEFAULT 'actionable',
    ADD COLUMN disposition_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN line_number INTEGER NOT NULL DEFAULT 1;
