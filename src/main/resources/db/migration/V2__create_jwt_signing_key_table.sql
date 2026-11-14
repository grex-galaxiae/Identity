CREATE TABLE jwt_signing_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key_id UUID,
    public_key TEXT,
    private_key TEXT,
    rotated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT jwt_signing_key_complete CHECK (
        (key_id IS NULL AND public_key IS NULL AND private_key IS NULL AND rotated_at IS NULL)
        OR
        (key_id IS NOT NULL AND public_key IS NOT NULL AND private_key IS NOT NULL AND rotated_at IS NOT NULL)
    )
);

-- The row exists before any instance starts generating keys, so FOR UPDATE serializes initialization.
INSERT INTO jwt_signing_key (id) VALUES (1);
