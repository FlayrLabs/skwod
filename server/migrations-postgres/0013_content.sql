-- Build 44 "content".

-- When a channel was last cleared. A device that was offline for the `channel_cleared` event
-- learns it from the next history page and purges what it cached from before.
ALTER TABLE channels ADD COLUMN cleared_at BIGINT;
