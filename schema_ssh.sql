CREATE TABLE IF NOT EXISTS ssh_hosts(
    h_id INTEGER PRIMARY KEY,
    host TEXT,
    port INTEGER,
    ip TEXT,
    hostname TEXT,
    UNIQUE(host, port)
);


CREATE TABLE IF NOT EXISTS ssh_scans(
    id INTEGER PRIMARY KEY,
    h_id INTEGER,

    version TEXT,
    DSA TEXT,
    RSA TEXT,
    ECDSA TEXT,
    EdDSA TEXT,

    firstscan REAL,
    lastscan  REAL,
    FOREIGN KEY (h_id) REFERENCES ssh_host(h_id)
);
