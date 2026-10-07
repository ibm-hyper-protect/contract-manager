-- 015_add_contract_downloaded_build_status.up.sql
-- Adds terminal status after ENV_OPERATOR acknowledges contract download.

ALTER TYPE build_status ADD VALUE IF NOT EXISTS 'CONTRACT_DOWNLOADED';
