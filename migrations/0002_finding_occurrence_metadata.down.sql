ALTER TABLE finding_occurrences
    DROP COLUMN IF EXISTS line_number,
    DROP COLUMN IF EXISTS disposition_reason,
    DROP COLUMN IF EXISTS disposition;
