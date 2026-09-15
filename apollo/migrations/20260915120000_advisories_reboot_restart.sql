-- migrate:up
alter table red_hat_advisories
  add column if not exists reboot_suggested boolean not null default false;
alter table red_hat_advisories
  add column if not exists restart_suggested boolean not null default false;

alter table advisories
  add column if not exists reboot_suggested boolean not null default false;
alter table advisories
  add column if not exists restart_suggested boolean not null default false;


-- migrate:down
alter table advisories
  drop column if exists reboot_suggested;
alter table advisories
  drop column if exists restart_suggested;

alter table red_hat_advisories
  drop column if exists reboot_suggested;
alter table red_hat_advisories
  drop column if exists restart_suggested;
