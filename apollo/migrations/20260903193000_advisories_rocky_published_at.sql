-- migrate:up
alter table advisories
  add column if not exists rocky_published_at timestamptz;

create index if not exists advisories_rocky_published_atx
  on advisories (rocky_published_at);


-- migrate:down
drop index if exists advisories_rocky_published_atx;
alter table advisories
  drop column if exists rocky_published_at;
