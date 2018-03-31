import certifi
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

backend = default_backend()


class Validator:
    MAX_DEPTH = 4

    def __init__(self, roots, get_extra_by_name):
        self.roots = roots
        self.roots_by_name = {}
        for root in self.roots:
            self.roots_by_name.setdefault(root.subject, []).append(root)
        self.get_extra_by_name = get_extra_by_name

    def extend_chain(self, certs, _depth=0):
        if _depth >= self.MAX_DEPTH:
            return []
        for issuer in self.roots_by_name.get(certs[0].issuer, []):
            trial = [issuer] + certs
            try:
                if self.is_valid_chain(trial):
                    return trial
            except UnsupportedAlgorithm:
                continue
        for issuer in self.get_extra_by_name(certs[0].issuer):
            result = self.extend_chain([issuer] + certs, _depth+1)
            if result:
                return result
        return []

    def is_valid_chain(self, chain):
        for i in range(len(chain)-1):
            issuer = chain[i]
            subject = chain[i+1]
            public_key = issuer.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                try:
                    public_key.verify(
                        subject.signature,
                        subject.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        subject.signature_hash_algorithm,
                    )
                except InvalidSignature:
                    return False
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                try:
                    public_key.verify(
                        subject.signature,
                        subject.tbs_certificate_bytes,
                        ec.ECDSA(subject.signature_hash_algorithm),
                    )
                except InvalidSignature:
                    return False
        return True


def get_store():
    store = []
    with open(certifi.where(), "rb") as f:
        store_pem = f.read()
    while store_pem:
        head, sep, store_pem = store_pem.partition(b"-----END CERTIFICATE-----")
        pemdata = head + sep
        if not pemdata.strip():
            break
        cert = x509.load_pem_x509_certificate(pemdata, backend)
        store.append(cert)
    return store
