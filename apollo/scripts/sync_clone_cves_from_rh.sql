-- Replace Rocky clone CVE membership with the current Red Hat advisory set.
-- Package NEVRAs are not touched. Safe to re-run.
--
-- Classify first:
--   psql ... -c "$(sed -n '/^-- CLASSIFY/,/^-- SYNC/p' this file | sed '1d;$d')"
-- Then apply:
--   psql ... -f apollo/scripts/sync_clone_cves_from_rh.sql

BEGIN;

-- CLASSIFY
SELECT
  count(*) FILTER (WHERE extra > 0 OR missing > 0) AS disagree,
  count(*) FILTER (WHERE extra > 0) AS clone_has_extra,
  count(*) FILTER (WHERE missing > 0) AS clone_missing,
  coalesce(sum(extra), 0) AS extra_cve_rows,
  coalesce(sum(missing), 0) AS missing_cve_rows
FROM (
  SELECT a.id,
    (
      SELECT count(*) FROM advisory_cves ac
      WHERE ac.advisory_id = a.id
        AND NOT EXISTS (
          SELECT 1 FROM red_hat_advisory_cves rh
          WHERE rh.red_hat_advisory_id = a.red_hat_advisory_id
            AND rh.cve = ac.cve
        )
    ) AS extra,
    (
      SELECT count(*) FROM red_hat_advisory_cves rh
      WHERE rh.red_hat_advisory_id = a.red_hat_advisory_id
        AND NOT EXISTS (
          SELECT 1 FROM advisory_cves ac
          WHERE ac.advisory_id = a.id AND ac.cve = rh.cve
        )
    ) AS missing
  FROM advisories a
  WHERE a.red_hat_advisory_id IS NOT NULL
) d;

-- SYNC
DELETE FROM advisory_cves ac
USING advisories a
WHERE ac.advisory_id = a.id
  AND a.red_hat_advisory_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM red_hat_advisory_cves rh
    WHERE rh.red_hat_advisory_id = a.red_hat_advisory_id
      AND rh.cve = ac.cve
  );

INSERT INTO advisory_cves (
  advisory_id, cve, cvss3_scoring_vector, cvss3_base_score, cwe
)
SELECT a.id, rh.cve, rh.cvss3_scoring_vector, rh.cvss3_base_score, rh.cwe
FROM advisories a
JOIN red_hat_advisory_cves rh ON rh.red_hat_advisory_id = a.red_hat_advisory_id
WHERE NOT EXISTS (
  SELECT 1 FROM advisory_cves ac
  WHERE ac.advisory_id = a.id AND ac.cve = rh.cve
);

COMMIT;
