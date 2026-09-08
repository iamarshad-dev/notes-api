CREATE TABLE notes (
    id  BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL,

    title VARCHAR(255) NOT NULL,
    content TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_notes_user
                   FOREIGN KEY (user_id)
                   REFERENCES users(id)
                   ON DELETE CASCADE
);

CREATE INDEX idx_notes_user_id
    ON notes(user_id);

CREATE INDEX idx_notes_user_created_at
    ON notes(user_id, created_at DESC);