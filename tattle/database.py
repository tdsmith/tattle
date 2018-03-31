from itertools import islice
from typing import Iterable, Iterator, List, Optional, Tuple

import apsw
import attr

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    state TEXT
);

CREATE TABLE IF NOT EXISTS certificates (
    sha1 BLOB,
    certificate_der BLOB,
    source INTEGER,
    FOREIGN KEY(source) REFERENCES sources(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS certificates_sha1 ON certificates (sha1);
CREATE INDEX IF NOT EXISTS certificates_source ON certificates (source);

CREATE TABLE IF NOT EXISTS certdata (
    sha1 BLOB,
    intermediate BOOLEAN,
    not_before_y_m TEXT,
    sha256 BLOB,
    issuer_der BLOB,
    FOREIGN KEY(sha1) REFERENCES certificates(sha1)
);
CREATE UNIQUE INDEX IF NOT EXISTS certdata_sha1 ON certdata(sha1);
CREATE UNIQUE INDEX IF NOT EXISTS certdata_sha256 ON certdata (sha256);
CREATE INDEX IF NOT EXISTS certdata_notbefore ON certdata (not_before_y_m);
CREATE INDEX IF NOT EXISTS certdata_intermediate ON certdata (intermediate)
    WHERE intermediate == 1;
CREATE INDEX IF NOT EXISTS certdata_issuer ON certdata (issuer_der);

CREATE TABLE IF NOT EXISTS trusted_intermediates (
    sha256 BLOB,
    name_der BLOB
);
CREATE UNIQUE INDEX IF NOT EXISTS intermediate_sha256 ON trusted_intermediates (sha256);
CREATE INDEX IF NOT EXISTS intermediate_name ON trusted_intermediates (name_der);

CREATE TABLE IF NOT EXISTS visibility (
    sha256 BLOB,
    status TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS visibility_sha256 ON visibility(sha256);
"""


@attr.s
class CertData:
    sha1: bytes = attr.ib()
    intermediate: bool = attr.ib()
    not_before_y_m: Optional[str] = attr.ib()
    sha256: bytes = attr.ib()
    issuer_der: Optional[bytes] = attr.ib()


class Database:
    _url_states = [
        "new",  # URL seen but not visited
        "fetched",  # certificates are in `certificates` but not `certdata`
        "parsed",  # certificate metadata is in `certdata`
    ]

    _visibility_states = [
        "untrusted",
        "known",
        "new",
        "reported",
    ]

    def __init__(self, filename: str):
        self._db = apsw.Connection(filename)
        self._db.setbusytimeout(600*1000)  # ms
        self._db.cursor().execute("PRAGMA journal_mode = WAL")
        with self._db as db:
            db.cursor().execute(SCHEMA)

    def update_urls(self, urls: List[str]) -> None:
        """Add new sources to the `sources` table."""
        statement = 'INSERT OR IGNORE INTO sources (url, state) VALUES (?, "new")'
        with self._db as db:
            db.cursor().executemany(statement, [(i,) for i in urls])

    def get_sources_with_state(self, state: str) -> List[str]:
        if state not in self._url_states:
            raise ValueError(f"status ({state}) must be one of " +
                             ','.join(self._url_states))
        cursor = self._db.cursor()
        cursor.execute("SELECT url FROM sources WHERE state == ?", (state,))
        return [row[0] for row in cursor]

    def set_source_state(self, source_url: str, state: str) -> None:
        statement = "UPDATE sources SET state = ? WHERE url = ?"
        with self._db as db:
            db.cursor().execute(statement, (state, source_url))

    def load_certs(self, source_url: str, certificates: Iterable[Tuple[bytes, bytes]]) -> None:
        source_id = (self._db.cursor().
                     execute("SELECT id FROM sources WHERE url == ?", (source_url,)).
                     fetchone()[0])
        statement = ("INSERT OR IGNORE INTO certificates (source, sha1, certificate_der) "
                     f"VALUES ({source_id}, ?, ?)")
        with self._db as db:
            db.cursor().executemany(statement, certificates)

    def iter_cert_der_from_source(
            self,
            source_url: str,
            chunk_size: int = 10000,
    ) -> Iterator[Tuple[bytes, bytes]]:
        statement = """
            SELECT c.sha1, c.certificate_der FROM
            certificates c INNER JOIN sources s
            ON c.source == s.id
            WHERE s.url == ?
        """
        cursor = self._db.cursor()
        result = cursor.execute(statement, (source_url,))
        while True:
            # realize a chunk
            chunk = list(islice(result, chunk_size))
            if not chunk:
                return
            yield from chunk

    def load_certdata(self, certdata: Iterable[CertData]):
        statement = ("INSERT OR IGNORE INTO certdata "
                     "(sha1, intermediate, not_before_y_m, sha256, issuer_der) "
                     "VALUES (?, ?, ?, ?, ?)")
        with self._db as db:
            db.cursor().executemany(
                statement,
                ((d.sha1, d.intermediate, d.not_before_y_m, d.sha256, d.issuer_der)
                 for d in certdata),
            )

    def get_intermediates(self):
        statement = ("SELECT c.certificate_der FROM "
                     "certificates c INNER JOIN certdata d "
                     "USING (sha1) "
                     "WHERE d.intermediate = 1")
        return [row[0] for row in self._db.cursor().execute(statement)]

    def load_trusted_intermediates(self, values):
        statement = ("INSERT OR IGNORE INTO trusted_intermediates "
                     "(sha256, name_der) VALUES (?, ?)")
        with self._db as db:
            cursor = db.cursor()
            cursor.execute("DELETE FROM trusted_intermediates")
            cursor.executemany(statement, values)

    def chunk_iter_novel_trustable_certs(self, chunk_size: int = 10000):
        statement = """
            SELECT c.certificate_der FROM certificates c
            INNER JOIN (SELECT d.sha1 FROM certdata d
              INNER JOIN (SELECT DISTINCT name_der FROM trusted_intermediates) i
              ON d.issuer_der == i.name_der)
            USING (sha1)
            WHERE sha1 NOT IN
              (SELECT sha1 FROM visibility LEFT JOIN certdata USING (sha256))
        """
        cursor = self._db.cursor()
        cursor.execute(statement)
        while True:
            chunk = list(row[0] for row in islice(cursor, chunk_size))
            if not chunk:
                return
            yield chunk

    def get_trusted_intermediate_certs(self):
        statement = """
            SELECT c.certificate_der FROM
              (SELECT i.name_der, d.sha1 FROM trusted_intermediates i
               LEFT JOIN certdata d USING (sha256)) i2
            LEFT JOIN certificates c USING (sha1)
        """
        return [row[0] for row in self._db.cursor().execute(statement)]

    def load_visibility(self, values):
        statement = """
            INSERT OR REPLACE INTO visibility (sha256, status) VALUES (?, ?)
        """
        with self._db as db:
            db.cursor().executemany(statement, values)

    def chunk_iter_certs_by_visibility_state(self, state, chunk_size=10000):
        statement = """
            SELECT c.certificate_der FROM
              (SELECT sha1 FROM certdata INNER JOIN visibility v USING (sha256)
               WHERE v.status == ?)
            INNER JOIN certificates c USING (sha1)
        """
        cursor = self._db.cursor()
        cursor.execute(statement, (state,))
        while True:
            chunk = list(row[0] for row in islice(cursor, chunk_size))
            if not chunk:
                return
            yield chunk
