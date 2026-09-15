-- migrate:up
alter table nvd_cves
  add column if not exists epss_score text,
  add column if not exists epss_percentile text,
  add column if not exists exploit_maturity text,
  add column if not exists kev_listed boolean not null default false,
  add column if not exists kev_date_added timestamptz,
  add column if not exists cpes jsonb;

create index if not exists nvd_cves_kev_listed_idx on nvd_cves (kev_listed) where kev_listed;


-- migrate:down
drop index if exists nvd_cves_kev_listed_idx;
alter table nvd_cves
  drop column if exists epss_score,
  drop column if exists epss_percentile,
  drop column if exists exploit_maturity,
  drop column if exists kev_listed,
  drop column if exists kev_date_added,
  drop column if exists cpes;
