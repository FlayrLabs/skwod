-- Build 45: which device wrote the account's key backup — the device a restore of that backup
-- brings back. A new sign-in that asks to restore a backup whose recovery key is still young
-- cannot be handed the backup yet (so it cannot name the device itself); the request is filed
-- against this device, where the account's other devices approve or refuse it
-- (`request_backup` in keydir.rs). NULL for a backup written before this column existed.
ALTER TABLE e2ee_key_backups ADD COLUMN device_id TEXT;
