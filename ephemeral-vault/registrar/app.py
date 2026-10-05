"""
Registrar Lambda (ps-ephemeral-vault-registrar)

This whole feature lives under the top-level ephemeral-vault/ folder
specifically so it's a pure addition to the existing repo -- nothing here
shares a path, a Lambda function name, or a buildspec with whatever is
already deployed. Deployed by a *separate* CodeBuild project pointed at
../buildspec.ephemeral-vault.yml (not the repo's existing buildspec.yml),
which packages this directory's *.py files together with config/ and
teams/ (so the deployed zip is self-contained -- this file reads
teams/<team>/envs/<env>.json and config/shared.json as paths relative to
/var/task at runtime, not from the rest of the repo) and deploys to
ps-ephemeral-vault-registrar specifically, never touching any existing
Lambda function.

Invoked directly (event = {"team": "...", "env": "...", "rotate": false})
and indirectly by scripts/reconcile.py --apply. For the named team, it:
  1. Reads teams/<team>/envs/<env>.json for desired state
  2. Ensures the shared trust anchor exists, pointed at the one shared
     self-hosted step-ca root certificate (see config/shared.json)
  3. Ensures the team's profile exists, with its CN attribute mapping
  4. Ensures the team's cert/key pair exists in Password Safe Secrets Safe

This Lambda's execution role needs rolesanywhere:CreateTrustAnchor,
UpdateTrustAnchor, ListTrustAnchors, CreateProfile, UpdateProfile,
ListProfiles, PutAttributeMapping (see infra/registrar-lambda.yaml), plus
network reachability to both the Password Safe API and the self-hosted
step-ca instance (see config/shared.json's "step_ca" block) -- step-ca
replaced ACM PCA as the free/open-source option, so there's no acm-pca IAM
permission needed any more, but there IS now a network dependency on
wherever step-ca is running (a VPC config on this Lambda, most likely).
"""
import json
import logging

from cert_issuer import issue_workload_certificate
from password_safe_client import PasswordSafeClient
from roles_anywhere import ensure_profile, ensure_shared_trust_anchor

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SHARED_INFRA_SAFE = "shared-infra"
PROVISIONER_KEY_SECRET_TITLE = "step-ca-provisioner-jwk"


def load_team_config(team_name, env_name="prod"):
    with open(f"teams/{team_name}/envs/{env_name}.json") as f:
        return json.load(f)


def load_shared_config():
    """
    One CA + one trust anchor for every team (see config/shared.json) --
    the cheap option: a self-hosted step-ca instance (just the cost of a
    small VM/container) instead of $400/month per team for a dedicated
    ACM PCA each. Per-team isolation comes from the IAM role trust policy,
    not from separate CAs (see roles_anywhere.DEFAULT_ATTRIBUTE_MAPPINGS
    and infra/example-team-role-trust-policy.json).
    """
    with open("config/shared.json") as f:
        return json.load(f)


def load_step_ca_config(shared_config, ps_client):
    """
    Assemble everything cert_issuer.issue_workload_certificate() needs to
    talk to step-ca. Only the provisioner's private JWK is sensitive --
    that lives in Password Safe (a dedicated "shared-infra" safe, separate
    from any team's safe), fetched fresh on every call rather than cached,
    the same way a team's cert/key is never written anywhere but memory
    and Password Safe.
    """
    step_ca = shared_config["step_ca"]
    safe = ps_client.ensure_safe(SHARED_INFRA_SAFE)
    provisioner_jwk_json = ps_client.get_file_secret_content(safe["Id"], PROVISIONER_KEY_SECRET_TITLE)

    return {
        "url": step_ca["url"],
        "root_cert_pem_path": step_ca["root_cert_pem_path"],
        "provisioner_name": step_ca["provisioner_name"],
        "provisioner_kid": step_ca["provisioner_kid"],
        "provisioner_jwk_json": provisioner_jwk_json,
    }


def provision_team(team_name, env_name="prod", rotate=False):
    """
    Ensure the team's profile exists (cheap, idempotent, safe to run on
    every pipeline deploy) against the shared trust anchor, and ensure a
    workload cert/key pair exists in Password Safe.

    Certificate issuance is NOT idempotent-cheap -- each call issues a
    brand new certificate from step-ca -- so by default this only issues
    one when the team has none yet. Pass rotate=True to force a fresh
    certificate and overwrite what's in Password Safe (see
    rotate_team_certificate() below and reconcile.py --rotate). Certs
    default to a 7-day validity (see cert_issuer.py), so rotation needs to
    run on a schedule shorter than cert_validity_days -- this isn't
    optional the way it was with a long-lived cert.
    """
    config = load_team_config(team_name, env_name)
    shared_config = load_shared_config()

    with open(shared_config["step_ca"]["root_cert_pem_path"]) as f:
        ca_bundle_pem = f.read()
    trust_anchor = ensure_shared_trust_anchor(ca_bundle_pem, shared_config["trust_anchor_name"])

    profile = ensure_profile(
        team_name,
        role_arns=config["role_arns"],
        duration_seconds=config.get("duration_seconds", 3600),
    )

    ps_client = PasswordSafeClient()
    ps_client.sign_in()
    try:
        safe = ps_client.ensure_safe(team_name)

        if rotate or not ps_client.has_certificate_secret(safe["Id"], team_name):
            step_ca_config = load_step_ca_config(shared_config, ps_client)
            private_key_pem, certificate_pem = issue_workload_certificate(
                step_ca_config,
                common_name=config.get("cert_common_name", f"{team_name}-workload"),
                validity_days=config.get("cert_validity_days", 7),
            )
            ps_client.upsert_certificate_secret(
                safe["Id"], team_name, certificate_pem, private_key_pem, overwrite=rotate
            )
    finally:
        ps_client.sign_out()

    logger.info(
        "Provisioned team=%s trust_anchor=%s profile=%s rotate=%s",
        team_name, trust_anchor.get("trustAnchorId"), profile.get("profileId"), rotate,
    )
    return {
        "team": team_name,
        "trustAnchorId": trust_anchor.get("trustAnchorId"),
        "profileId": profile.get("profileId"),
    }


def rotate_team_certificate(team_name, env_name="prod"):
    """Force a fresh certificate even if one already exists. See provision_team()."""
    return provision_team(team_name, env_name, rotate=True)


def handler(event, context):
    team_name = event["team"]
    env_name = event.get("env", "prod")
    rotate = event.get("rotate", False)
    result = provision_team(team_name, env_name, rotate=rotate)
    return {"statusCode": 200, "body": json.dumps(result)}
