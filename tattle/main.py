from base64 import b64decode
from binascii import hexlify, unhexlify
from datetime import datetime
from functools import partial
import logging
import gzip
import sys

from cryptography import x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from joblib import Parallel, delayed
import psycopg2
import requests

from .database import CertData, Database
from .trust import Validator, get_store

DATABASE = "tattle.db"
SCANS_URL = "https://scans.io/json"

logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stderr)
logger.setLevel(logging.DEBUG)

backend = default_backend()


def load_scans(db):
    scans = requests.get(SCANS_URL).json()
    moressl = [study for study in scans["studies"] if study["uniqid"] == "sonar.moressl"][0]
    cert_files = sorted([
        file["name"] for file in moressl["files"]
        if file["name"].endswith("_certs.gz")])
    db.update_urls(cert_files)


def load_certificates(db_factory, url):
    db = db_factory()
    logger.info("Fetching %s", url)
    r = requests.get(url)
    logger.info("Parsing %s", url)
    csv = gzip.decompress(r.content)
    values = []
    for line in csv.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        sha1, cert = line.split(b",", 1)
        values.append((sha1, b64decode(cert)))
    db.load_certs(url, values)
    db.set_source_state(url, "fetched")


def parse_certs_from_source(db_factory, url):
    db = db_factory()
    logger.info("Parsing certificates from %s", url)
    values = []
    for sha1, der in db.iter_cert_der_from_source(url):
        try:
            cert = load_der_x509_certificate(der, backend)
        except Exception as e:
            logger.debug("Exception while loading: %r", e)
            continue

        try:
            self_signed = cert.issuer == cert.subject
        except Exception as e:
            logger.debug("Exception while parsing names: %r", e)
            self_signed = True  # it's useless as a CA, anyway.

        maybe_ca = True
        try:
            constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            maybe_ca = constraints.value.ca
        except x509.ExtensionNotFound:
            pass
        except Exception as e:
            logger.debug("Exception while checking basic constraints: %r", e)

        try:
            not_before_y_m = cert.not_valid_before.strftime("%Y-%m")
        except Exception as e:
            logger.debug("Exception while parsing date: %r", e)
            not_before_y_m = None

        intermediate = (not self_signed) and maybe_ca
        sha256 = hexlify(cert.fingerprint(hashes.SHA256()))

        try:
            issuer_der = cert.issuer.public_bytes(backend)
        except Exception as e:
            logger.debug("Exception while serializing issuer: %r", e)
            issuer_der = None

        values.append(CertData(
            sha1=sha1,
            intermediate=intermediate,
            not_before_y_m=not_before_y_m,
            sha256=sha256,
            issuer_der=issuer_der,
        ))

    db.load_certdata(values)
    db.set_source_state(url, "parsed")


def trust_intermediates(db):
    # Construct chains to intermediates
    logger.info("Loading intermediates")
    intermediates = db.get_intermediates()

    logger.info("Parsing intermediates")
    certs = [load_der_x509_certificate(der, backend) for der in intermediates]
    by_name = {}
    for cert in certs:
        by_name.setdefault(cert.subject, []).append(cert)

    logger.info("Trusting intermediates")
    get_by_name = lambda x: by_name.get(x, [])
    v = Validator(get_store(), get_by_name)
    trust_chains = [v.extend_chain([cert]) for cert in certs]

    logger.info("Serializing intermediates")
    values = []
    for chain in trust_chains:
        if not chain:
            continue
        intermediate = chain[-1]
        sha256 = hexlify(intermediate.fingerprint(hashes.SHA256()))
        try:
            name_der = intermediate.subject.public_bytes(backend)
        except Exception:
            continue
        values.append((sha256, name_der))

    db.load_trusted_intermediates(values)


def novel_to_crt_sh(cids, digest="sha256"):
    assert digest in ("sha256", "sha1")
    conn = psycopg2.connect(dbname="certwatch", user="guest", host="crt.sh", port=5432)
    querystring = """
        SELECT digest(c.certificate, %s) FROM certificate c
        WHERE digest(c.certificate, %s) = ANY(%s)
    """
    cursor = conn.cursor()
    cursor.execute(querystring, (digest, digest, [unhexlify(i) for i in cids]))
    results = set(hexlify(row[0]) for row in cursor.fetchall())
    cursor.close()
    conn.close()
    return set(cids) - results


def check_novelty(db_factory, chunk):
    db = db_factory()
    logger.debug("Deserializing end-entity certs")
    certs = []
    for der in chunk:
        try:
            cert = load_der_x509_certificate(der, backend)
            certs.append(cert)
        except Exception as e:
            logger.debug("Exception while deserializing certs: %r")

    dispositions = []

    fingerprints = []
    for cert in certs:
        sha256 = hexlify(cert.fingerprint(hashes.SHA256()))
        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)[0].value
            if issuer_org == "Let's Encrypt":
                dispositions.append((sha256, "known"))
                continue
        except Exception:
            pass
        fingerprints.append(sha256)

    logger.debug("Checking crt.sh")
    novel = novel_to_crt_sh(fingerprints)

    for h in fingerprints:
        status = "new" if h in novel else "known"
        dispositions.append((h, status))

    db.load_visibility(dispositions)


def report_novel_certs(db_factory, chunk):
    db = db_factory()

    logger.debug("Deserializing intermediates")
    intermediate_der = db.get_trusted_intermediate_certs()
    intermediates_by_name = {}
    for der in intermediate_der:
        cert = load_der_x509_certificate(der, backend)
        intermediates_by_name.setdefault(cert.subject, []).append(cert)
    v = Validator(get_store(), lambda x: intermediates_by_name.get(x, []))

    logger.debug("Deserializing end-entity certs")
    certs = []
    for der in chunk:
        try:
            cert = load_der_x509_certificate(der, backend)
            certs.append(cert)
        except Exception as e:
            logger.debug("Exception while deserializing certs: %r")

    dispositions = []
    now = datetime.now()

    logger.debug("Trusting novel certs")
    for cert in certs:
        sha256 = hexlify(cert.fingerprint(hashes.SHA256()))
        chain = v.extend_chain([cert])
        if not chain:
            dispositions.append((sha256, "untrusted"))
            continue

        expired = True
        try:
            if cert.not_valid_after > now:
                expired = False
        except Exception as e:
            logger.debug("Exception while checking dates: %r", e)

        fate = "expired" if expired else "valid"
        asciiprint = sha256.decode("ascii")
        path = f"discovered/{fate}/{asciiprint}.pem"
        with open(path, "wb") as f:
            for cert in chain[::-1]:
                f.write(cert.public_bytes(Encoding.PEM))
        dispositions.append((sha256, "reported"))

    db.load_visibility(dispositions)


def main():
    db = Database(DATABASE)
    logger.info("Scanning study catalog")
    load_scans(db)

    db_factory = partial(Database, DATABASE)
    urls = db.get_sources_with_state("new")
    Parallel(n_jobs=-1)(delayed(load_certificates)(db_factory, url) for url in urls)

    urls = db.get_sources_with_state("fetched")
    dirty = True if urls else False
    Parallel(n_jobs=-2)(delayed(parse_certs_from_source)(db_factory, url) for url in urls)

    if dirty:
        # The advantage of parallelizing this is smaller than you'd imagine
        # since all processes need to be able to see all intermediates in order
        # to make trust decisions, and deserializing the certificates takes
        # more time than making trust decisions.
        trust_intermediates(db)

    logger.info("Searching certificates")
    chunks = db.chunk_iter_novel_trustable_certs(chunk_size=50000)
    Parallel(n_jobs=-2)(delayed(check_novelty)(db_factory, chunk) for chunk in chunks)

    logger.info("Reporting new certificates")
    chunks = db.chunk_iter_certs_by_visibility_state("new")
    Parallel(n_jobs=-2)(delayed(report_novel_certs)(db_factory, chunk) for chunk in chunks)


if __name__ == "__main__":
    main()
