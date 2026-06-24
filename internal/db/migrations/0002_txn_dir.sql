-- txn_dir records directories a transaction may create during staging.
-- They are removed during rollback in reverse order, after txn_file
-- rows have restored or discarded payload content.

CREATE TABLE txn_dir (
    txn_id INTEGER NOT NULL,
    seq    INTEGER NOT NULL,
    path   TEXT    NOT NULL,

    PRIMARY KEY (txn_id, path),
    UNIQUE (txn_id, seq),

    FOREIGN KEY (txn_id) REFERENCES txn (id) ON DELETE CASCADE
);
