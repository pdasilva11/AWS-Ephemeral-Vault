"""
cert_issuer.py

Issues a fresh workload certificate from a self-hosted step-ca instance at
provisioning time -- the free/open-source replacement for ACM PCA (no
$50-$400/month CA operation fee; step-ca itself costs only whatever tiny
VM or container it runs on). The private key is generated here, in memory,
with the `cryptography` library, and is never written to disk or to
teams/*/envs/*.json -- only the resulting PEM strings are returned, for
the caller (registrar/app.py) to hand straight to Password Safe.

step-ca authenticates signing requests with a JWK provisioner: the caller
proves it's allowed to request a cert by presenting a short-lived JWT
("one-time token", OTT) signed with a provisioner private key that only
the registrar holds (stored in Password Safe, not here -- see
load_provisioner_key() in app.py). This plays the same role ACM PCA's IAM
permissions played: it's what stops anyone who can reach step-ca's HTTP
endpoint from getting a cert issued.

TLS note: step-ca serves its API over HTTPS with a certificate signed by
itself (there's no public CA involved), so standard system trust stores
won't validate it. requests' `verify=` parameter is pointed at the step-ca
root certificate's own PEM (public, non-secret, see config/shared.json)
instead of being disabled -- this still gets real TLS chain validation,
just pinned to this specific root rather than a public CA bundle.
"""
import time
import uuid

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jwcrypto import jwk, jws
from jwcrypto.common import json_encode


def _build_ott(provisioner_jwk_json, provisioner_kid, provisioner_name, ca_sign_url, common_name, ttl_seconds=300):
    """
    Build the one-time-token step-ca's JWK provisioner expects: a compact
    JWS whose payload matches what `step ca token` would generate. See
    https://smallstep.com/docs/step-ca/provisioners/#jwk for the exact
    claim shape this mirrors (aud/iss/sub/sha/sans/exp/nbf/iat/jti).

    This has NOT been tested against a live step-ca instance in this
    session -- verify the claim set against your step-ca version with
    `step ca token <name> | step crypto jwt inspect --insecure` and adjust
    if your version differs before relying on it.
    """
    key = jwk.JWK.from_json(provisioner_jwk_json)
    now = int(time.time())

    payload = {
        "aud": ca_sign_url,
        "iss": provisioner_name,
        "sub": common_name,
        "sans": [common_name],
        "sha": key.thumbprint(),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }

    token = jws.JWS(json_encode(payload).encode("utf-8"))
    token.add_signature(
        key,
        alg="ES256",
        protected=json_encode({"alg": "ES256", "kid": provisioner_kid, "typ": "JWT"}),
    )
    return token.serialize(compact=True)


def issue_workload_certificate(step_ca_config, common_name, validity_days=7, key_size=2048):
    """
    Generate a key pair + CSR in memory, have step-ca sign it, and return
    (private_key_pem, certificate_pem).

    step_ca_config is a dict with: url, root_cert_pem, provisioner_name,
    provisioner_kid, provisioner_jwk_json (the last one is the sensitive
    part -- it comes from Password Safe, see app.load_provisioner_key()).

    Default validity of 7 days mirrors the short-lived-cert pattern from
    the ACM PCA version of this design -- step-ca doesn't enforce a
    specific cap the way ACM PCA's short-lived mode does, so
    validity_days here is the real control; keep it short since rotation
    (reconcile.py --rotate) needs to outpace whatever you set.
    """
    sign_url = f"{step_ca_config['url']}/1.0/sign"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    ott = _build_ott(
        provisioner_jwk_json=step_ca_config["provisioner_jwk_json"],
        provisioner_kid=step_ca_config["provisioner_kid"],
        provisioner_name=step_ca_config["provisioner_name"],
        ca_sign_url=sign_url,
    )

    resp = requests.post(
        sign_url,
        json={"csr": csr_pem, "ott": ott, "notAfter": f"{validity_days * 24}h"},
        verify=step_ca_config["root_cert_pem_path"],
        timeout=15,
    )
    resp.raise_for_status()
    certificate_pem = resp.json()["crt"]

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return private_key_pem, certificate_pem
