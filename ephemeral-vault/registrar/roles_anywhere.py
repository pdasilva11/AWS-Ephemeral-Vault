"""
Helper functions for managing IAM Roles Anywhere trust anchors and profiles.

Called by the registrar Lambda using the Lambda's own IAM execution role
(ordinary SigV4 auth) -- this is the control-plane side. The workload-side
CreateSession call is a separate, certificate-signed request made by
aws_signing_helper (see workload/renewal/credential_process.py) and is NOT
made through this module or through boto3.
"""
import boto3

client = boto3.client("rolesanywhere")

# Certificate attributes to expose as session principal tags, so a shared
# trust anchor + CA can still be scoped per team at the IAM role trust
# policy level (condition on aws:PrincipalTag/x509Subject/CN). See
# ensure_profile() and infra/example-team-role-trust-policy.json.
DEFAULT_ATTRIBUTE_MAPPINGS = [
    {"certificateField": "x509Subject", "mappingRules": [{"specifier": "CN"}]},
]


def find_trust_anchor_by_name(name):
    paginator = client.get_paginator("list_trust_anchors")
    for page in paginator.paginate():
        for anchor in page["trustAnchors"]:
            if anchor["name"] == name:
                return anchor
    return None


def ensure_shared_trust_anchor(ca_bundle_pem, name="shared-trust-anchor"):
    """
    Create (or point) a single trust anchor shared by every team, backed by
    the self-hosted step-ca root certificate (CERTIFICATE_BUNDLE source --
    there's no ACM PCA involved with a free/open-source CA, so this is the
    root cert's PEM text, not an ARN). Trust anchors aren't billed, so this
    costs nothing beyond whatever step-ca itself runs on. Team isolation is
    enforced downstream at the IAM role trust policy, not by giving each
    team its own CA.

    ca_bundle_pem must be re-supplied (not just left as-is) if the step-ca
    root ever rotates, since IAM Roles Anywhere won't trust certificates
    signed by a root it doesn't have on file.
    """
    existing = find_trust_anchor_by_name(name)

    source = {
        "sourceType": "CERTIFICATE_BUNDLE",
        "sourceData": {"x509CertificateData": ca_bundle_pem},
    }

    if existing is None:
        resp = client.create_trust_anchor(name=name, source=source, enabled=True)
        return resp["trustAnchor"]

    client.update_trust_anchor(trustAnchorId=existing["trustAnchorId"], source=source)
    return existing


def find_profile_by_name(name):
    paginator = client.get_paginator("list_profiles")
    for page in paginator.paginate():
        for profile in page["profiles"]:
            if profile["name"] == name:
                return profile
    return None


def ensure_profile(team_name, role_arns, duration_seconds=3600):
    """
    Create or update the per-team profile that maps role(s) to sessions.

    Profiles (like trust anchors) aren't billed, so having one per team costs
    nothing even though all teams share one CA and trust anchor. The
    attribute mapping ensures the certificate's CN is exposed as
    aws:PrincipalTag/x509Subject/CN, which is what the team's IAM role trust
    policy conditions on for isolation (see
    infra/example-team-role-trust-policy.json) -- without this mapping, the
    condition key has no value and the policy evaluates to deny.

    duration_seconds governs the credential TTL (see CreateSession behavior):
    the effective session length is min(profile.durationSeconds, request
    durationSeconds), capped at 43200 (12h), floor 900 (15min). Default is
    3600 (1h) if omitted.
    """
    name = f"{team_name}-profile"
    existing = find_profile_by_name(name)

    if existing is None:
        resp = client.create_profile(
            name=name,
            roleArns=role_arns,
            durationSeconds=duration_seconds,
            enabled=True,
            tags=[{"key": "team", "value": team_name}],
        )
        profile = resp["profile"]
    else:
        client.update_profile(
            profileId=existing["profileId"],
            roleArns=role_arns,
            durationSeconds=duration_seconds,
        )
        profile = existing

    for mapping in DEFAULT_ATTRIBUTE_MAPPINGS:
        client.put_attribute_mapping(
            profileId=profile["profileId"],
            certificateField=mapping["certificateField"],
            mappingRules=mapping["mappingRules"],
        )

    return profile
