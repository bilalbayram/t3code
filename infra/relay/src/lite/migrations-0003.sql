-- The tunnel config the relay hands back when a server asks to recover its tunnel.
ALTER TABLE environments ADD COLUMN runtime_json TEXT;
