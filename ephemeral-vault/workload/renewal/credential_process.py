#!/usr/bin/env python3
"""
credential_process.py

An AWS SDK "credential_process" provider (see ~/.aws/config snippet below)
that:
  1. Signs in to Password Safe and retrieves this workload's cert + private
     key from Secrets Safe (never stored on disk outside this process's
     lifetime)
  2. Writes them to 0600 files in a private temp directory
  3. Shells out to AWS's aws_signing_helper to exchange the cert for
     temporary AWS credentials via IAM Roles Anywhere's CreateSession
  4. Prints the resulting JSON (process credential provider format) to
     stdout
  5. Shreds the temp cert/key files before exiting

Renewal is handled by the AWS SDK itself, not by this script: the SDK reads
the "Expiration" field in the JSON this script returns and re-invokes this
script automatically once the cached credentials are close to expiring. No
background daemon or sleep loop is needed -- just make sure this script
runs fast and reliably every time it's invoked.

~/.aws/config:
    [profile acme-payments]
    credential_process = python3 /opt/ephemeral-vault/credential_process.py --team acme-payments

Required env vars (set these from the team's provisioning output --
see registrar/app.py / teams/<team>/envs/<env>.json):
    ROLES_ANYWHERE_TRUST_ANCHOR_ARN
    ROLES_ANYWHERE_PROFILE_ARN
    ROLES_ANYWHERE_ROLE_ARN

Install aws_signing_helper first:
    https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html
"""
import argparse
import os
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "registrar"))
from password_safe_client import PasswordSafeClient  # noqa: E402

TRUST_ANCHOR_ARN_ENV = "ROLES_ANYWHERE_TRUST_ANCHOR_ARN"
PROFILE_ARN_ENV = "ROLES_ANYWHERE_PROFILE_ARN"
ROLE_ARN_ENV = "ROLES_ANYWHERE_ROLE_ARN"


def fetch_cert_and_key(team_name):
    ps_client = PasswordSafeClient()
    ps_client.sign_in()
    try:
        safe = ps_client.ensure_safe(team_name)
        secret_name = f"{team_name}-roles-anywhere"
        cert_pem = ps_client.get_file_secret_content(safe["Id"], f"{secret_name}-cert")
        key_pem = ps_client.get_file_secret_content(safe["Id"], f"{secret_name}-key")
        return cert_pem, key_pem
    finally:
        ps_client.sign_out()


def write_private(path, content):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600, owner read/write only


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--team", required=True)
    args = parser.parse_args()

    trust_anchor_arn = os.environ[TRUST_ANCHOR_ARN_ENV]
    profile_arn = os.environ[PROFILE_ARN_ENV]
    role_arn = os.environ[ROLE_ARN_ENV]

    cert_pem, key_pem = fetch_cert_and_key(args.team)

    tmpdir = tempfile.mkdtemp(prefix="ephemeral-vault-")
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")

    try:
        write_private(cert_path, cert_pem)
        write_private(key_path, key_pem)

        result = subprocess.run(
            [
                "aws_signing_helper", "credential-process",
                "--certificate", cert_path,
                "--private-key", key_path,
                "--trust-anchor-arn", trust_anchor_arn,
                "--profile-arn", profile_arn,
                "--role-arn", role_arn,
            ],
            capture_output=True, text=True, check=True,
        )
        # Pass the signing helper's process-credential-provider JSON straight through.
        # The credential TTL is whatever the profile's durationSeconds specifies
        # (see registrar/roles_anywhere.py) -- this script doesn't need its own
        # notion of TTL, it just gets invoked again whenever the SDK needs to.
        sys.stdout.write(result.stdout)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(exc.stderr)
        sys.exit(1)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
