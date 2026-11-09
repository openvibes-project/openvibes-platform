-- Windows hosts (#532, protocol P22): a Windows agent reports os id
-- `windows` and its version with build and update revision, so its
-- distribution reads "windows 10.0.26100.2894"; the display name says
-- "Windows 10.0.26100.2894", as host_group_facts.rs `distribution_name`.
-- Migration 53's function otherwise unchanged. Automatic distribution groups
-- stay Linux-only (migration 53's regex), so a monthly update revision never
-- makes a new group.
CREATE OR REPLACE FUNCTION console_distribution_name(distribution text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT COALESCE((CASE split_part(distribution, ' ', 1)
           WHEN 'debian' THEN 'Debian' WHEN 'ubuntu' THEN 'Ubuntu' WHEN 'fedora' THEN 'Fedora'
           WHEN 'rocky' THEN 'Rocky Linux' WHEN 'almalinux' THEN 'AlmaLinux' WHEN 'windows' THEN 'Windows' END)
         || substr(distribution, length(split_part(distribution, ' ', 1)) + 1), distribution) $$;
