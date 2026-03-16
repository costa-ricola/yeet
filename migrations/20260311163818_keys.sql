CREATE TABLE IF NOT EXISTS keys
(
    id              INTEGER PRIMARY KEY NOT NULL,
    keyid           TEXT    NOT NULL UNIQUE,
    verifying_key   BLOB    NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users
(
    id              INTEGER PRIMARY KEY NOT NULL,
    key_id          INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    level           TEXT    NOT NULL
);
