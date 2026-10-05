#!/usr/bin/env python3
"""
scripts/reconcile.py

Drift check: for a given team (or all teams if --team is omitted), compares
the desired state in teams/<team>/envs/*.json against the actual state in
IAM Roles Anywhere and Password Safe, and reports (or fixes, with --apply)
any mismatch. Run with CWD at ephemeral-vault/ (matches
buildspec.ephemeral-vault.yml's invocation: `cd ephemeral-vault &&
python scripts/reconcile.py --team "$TEAM" --apply`) -- the relative
teams/ and config/ paths resolve against that directory, not the repo root.

Usage:
    python scripts/reconcile.py --team acme-payments
    python scripts/reconcile.py --team acme-payments --apply
    python scripts/reconcile.py --apply   # reconcile every team
"""
import argparse
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "registrar"))

import app as registrar_app  # noqa: E402
from password_safe_client import PasswordSafeClient  # noqa: E402
from roles_anywhere import find_profile_by_name, find_trust_anchor_by_name  # noqa: E402


def discover_teams():
    paths = glob.glob("teams/*/envs/*.json")
    return sorted({p.split(os.sep)[1] for p in paths})


def check_shared_trust_anchor():
    """All teams share one trust anchor (and one CA) -- check it once, not per team."""
    shared_config = registrar_app.load_shared_config()
    trust_anchor = find_trust_anchor_by_name(shared_config["trust_anchor_name"])
    if trust_anchor is None:
        return ["missing shared trust anchor"]
    if not trust_anchor.get("enabled", True):
        return ["shared trust anchor disabled"]
    return []


def check_team(team_name, env_name="prod"):
    config = registrar_app.load_team_config(team_name, env_name)
    issues = []

    profile = find_profile_by_name(f"{team_name}-profile")
    if profile is None:
        issues.append("missing profile")
    elif sorted(profile.get("roleArns", [])) != sorted(config["role_arns"]):
        issues.append("profile role_arns out of date")
    elif profile.get("durationSeconds") != config.get("duration_seconds", 3600):
        issues.append("profile durationSeconds out of date")

    ps_client = PasswordSafeClient()
    ps_client.sign_in()
    try:
        safe = ps_client.ensure_safe(team_name)
        if not ps_client.has_certificate_secret(safe["Id"], team_name):
            issues.append("missing cert/key secret in Password Safe")
    finally:
        ps_client.sign_out()

    return issues


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--team", help="Reconcile a single team; omit to check all teams")
    parser.add_argument("--apply", action="store_true", help="Fix drift instead of just reporting it")
    parser.add_argument(
        "--rotate", action="store_true",
        help="With --apply, also force-issue a fresh cert/key for every team checked "
             "(use on a schedule ahead of cert_validity_days, not on every pipeline run)",
    )
    args = parser.parse_args()

    teams = [args.team] if args.team else discover_teams()
    exit_code = 0

    shared_issues = check_shared_trust_anchor()
    if shared_issues:
        print(f"[drift] shared trust anchor: {', '.join(shared_issues)}")
        exit_code = 1
        if args.apply and teams:
            # Any team's provision_team() call also ensures the shared trust
            # anchor, so fixing it piggybacks on the first team reconciled.
            print("[fixing] shared trust anchor via first team's provisioning")

    for team_name in teams:
        issues = check_team(team_name)
        if not issues and not args.rotate:
            print(f"[ok] {team_name}")
            continue

        if issues:
            print(f"[drift] {team_name}: {', '.join(issues)}")
            exit_code = 1

        if args.apply:
            registrar_app.provision_team(team_name, rotate=args.rotate)
            print(f"[rotated] {team_name}" if args.rotate else f"[fixed] {team_name}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
