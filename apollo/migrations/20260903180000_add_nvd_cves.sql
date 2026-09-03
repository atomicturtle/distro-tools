-- migrate:up
create table nvd_cves (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  updated_at timestamptz,
  cve_id varchar(32) not null,
  description text,
  cvss_v2_score text,
  cvss_v2_vector text,
  cvss_v3_score text,
  cvss_v3_vector text,
  cvss_v4_score text,
  cvss_v4_vector text,
  cwe text,
  refs jsonb,
  published_at timestamptz,
  last_modified_at timestamptz,
  fetched_at timestamptz not null,
  constraint nvd_cves_cve_id_key unique (cve_id)
);

create index nvd_cves_cve_id_idx on nvd_cves (cve_id);
create index nvd_cves_fetched_at_idx on nvd_cves (fetched_at);


-- migrate:down
drop table if exists nvd_cves;
