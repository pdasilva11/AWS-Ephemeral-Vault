"""
Thin client for BeyondTrust Password Safe's Secrets Safe REST API.

PLACEHOLDER VALUES: PS_BASE_URL / PS_API_KEY / PS_RUNAS_USER below are not
real credentials, and the endpoint paths follow the general Secrets Safe
REST shape (Safes / Secrets-Safe Secrets groups) documented at
https://docs.beyondtrust.com/bips/reference/introduction -- confirm exact
paths and payload field names against your tenant's live API reference
before using this against a real Password Safe instance.
"""
import os

import requests

PS_BASE_URL = os.environ.get(
    "PS_BASE_URL", "https://PLACEHOLDER-password-safe.example.com/BeyondTrust/api/public/v3"
)
PS_API_KEY = os.environ.get("PS_API_KEY", "PLACEHOLDER_API_KEY")
PS_RUNAS_USER = os.environ.get("PS_RUNAS_USER", "PLACEHOLDER_RUNAS_USER")


class PasswordSafeClient:
    def __init__(self):
        self.session = requests.Session()
        self._signed_in = False

    def sign_in(self):
        """POST Auth/SignAppin using the API key registered for this workload/registrar."""
        headers = {
            "Authorization": f"PS-Auth key={PS_API_KEY}; runas={PS_RUNAS_USER};",
            "Content-Type": "application/json",
        }
        resp = self.session.post(f"{PS_BASE_URL}/Auth/SignAppin", headers=headers, timeout=10)
        resp.raise_for_status()
        self._signed_in = True

    def sign_out(self):
        if self._signed_in:
            self.session.post(f"{PS_BASE_URL}/Auth/Signout", timeout=10)
            self._signed_in = False

    def ensure_safe(self, team_name):
        """Get or create the Secrets Safe 'Safe' that scopes this team's secrets."""
        resp = self.session.get(f"{PS_BASE_URL}/secrets-safe/safes", timeout=10)
        resp.raise_for_status()
        for safe in resp.json():
            if safe["Name"] == team_name:
                return safe

        create = self.session.post(
            f"{PS_BASE_URL}/secrets-safe/safes",
            json={
                "Name": team_name,
                "Description": f"IAM Roles Anywhere cert/key for team {team_name}",
            },
            timeout=10,
        )
        create.raise_for_status()
        return create.json()

    def list_secret_titles(self, safe_id):
        resp = self.session.get(f"{PS_BASE_URL}/secrets-safe/safes/{safe_id}/secrets", timeout=10)
        resp.raise_for_status()
        return [s["Title"] for s in resp.json()]

    def has_certificate_secret(self, safe_id, team_name):
        """True if this team already has a cert+key pair stored."""
        secret_name = f"{team_name}-roles-anywhere"
        titles = self.list_secret_titles(safe_id)
        return f"{secret_name}-cert" in titles and f"{secret_name}-key" in titles

    def upsert_certificate_secret(self, safe_id, team_name, cert_pem, key_pem, overwrite=False):
        """
        Store the cert + private key as two file secrets in the team's safe.
        cert_pem/key_pem are expected to come from cert_issuer.issue_workload_certificate()
        at provisioning time -- never from a value committed in teams/*/envs/*.json.

        By default this only creates secrets that don't exist yet (cheap,
        idempotent re-provisioning). Pass overwrite=True for an explicit
        rotation, which replaces both existing secrets with freshly issued
        material (see app.rotate_team_certificate / reconcile.py --rotate).
        """
        secret_name = f"{team_name}-roles-anywhere"
        existing = {
            s["Title"]: s["Id"]
            for s in self.session.get(
                f"{PS_BASE_URL}/secrets-safe/safes/{safe_id}/secrets", timeout=10
            ).json()
        }

        cert_title, key_title = f"{secret_name}-cert", f"{secret_name}-key"
        payload_cert = {"Title": cert_title, "FileContent": cert_pem}
        payload_key = {"Title": key_title, "FileContent": key_pem}

        if cert_title not in existing:
            self.session.post(
                f"{PS_BASE_URL}/secrets-safe/safes/{safe_id}/secrets/file",
                json=payload_cert, timeout=10,
            ).raise_for_status()
        elif overwrite:
            self.session.put(
                f"{PS_BASE_URL}/secrets-safe/secrets/file/{existing[cert_title]}",
                json=payload_cert, timeout=10,
            ).raise_for_status()

        if key_title not in existing:
            self.session.post(
                f"{PS_BASE_URL}/secrets-safe/safes/{safe_id}/secrets/file",
                json=payload_key, timeout=10,
            ).raise_for_status()
        elif overwrite:
            self.session.put(
                f"{PS_BASE_URL}/secrets-safe/secrets/file/{existing[key_title]}",
                json=payload_key, timeout=10,
            ).raise_for_status()

    def get_file_secret_content(self, safe_id, title):
        resp = self.session.get(f"{PS_BASE_URL}/secrets-safe/safes/{safe_id}/secrets", timeout=10)
        resp.raise_for_status()
        match = next((s for s in resp.json() if s["Title"] == title), None)
        if match is None:
            raise LookupError(f"secret '{title}' not found in safe {safe_id}")

        content = self.session.get(
            f"{PS_BASE_URL}/secrets-safe/secrets/file/{match['Id']}/file", timeout=10
        )
        content.raise_for_status()
        return content.text
