#!/usr/bin/env bash
# One-time bootstrap for a self-hosted step-ca instance (the free/open-source
# replacement for ACM PCA -- no $50-400/mo AWS CA fee, just whatever tiny
# VM or container runs this). Deliberately NOT run by
# buildspec.ephemeral-vault.yml or the registrar Lambda -- creating a CA's
# root key is a highly privileged, one-time action.
#
# This script covers steps 1-3 below (CA creation + starting the server).
# Step 4 (handing the registrar its provisioner credential) involves a
# private-key-decryption command whose exact syntax has varied across
# step-ca releases -- it's called out explicitly so you check it against
# `step crypto jwe decrypt --help` for your installed version before
# trusting the output.
#
# Prerequisites: step CLI and step-ca installed
# (https://smallstep.com/docs/step-cli/installation/).
set -euo pipefail

CA_NAME="Ephemeral Vault CA"
CA_DNS="${CA_DNS:?Set CA_DNS to the hostname/IP this CA will be reachable at, e.g. step-ca.internal}"
CA_ADDRESS="${CA_ADDRESS:-:9000}"
PROVISIONER_NAME="ephemeral-vault-registrar"
WORKDIR="$(mktemp -d)"

# --- Step 1: generate passwords (keep these -- you need them again later,
# e.g. to rotate the root or re-derive the provisioner key) ---
openssl rand -base64 32 > "$WORKDIR/ca-password.txt"
openssl rand -base64 32 > "$WORKDIR/provisioner-password.txt"
echo "CA password saved to:          $WORKDIR/ca-password.txt"
echo "Provisioner password saved to: $WORKDIR/provisioner-password.txt"
echo "Move both somewhere durable (e.g. Password Safe) before this tmpdir is cleaned up."

# --- Step 2: initialize the CA (root + intermediate + one JWK provisioner) ---
step ca init \
  --name "$CA_NAME" \
  --dns "$CA_DNS" \
  --address "$CA_ADDRESS" \
  --provisioner "$PROVISIONER_NAME" \
  --password-file "$WORKDIR/ca-password.txt" \
  --provisioner-password-file "$WORKDIR/provisioner-password.txt" \
  --deployment-type standalone

STEP_PATH="$(step path)"
echo ""
echo "CA initialized at $STEP_PATH"
echo "Root certificate (public, commit this): $STEP_PATH/certs/root_ca.crt"
echo "  -> copy its contents into ephemeral-vault/config/step-ca-root.pem"

# --- Step 3: run the CA as a persistent service ---
# For anything beyond a quick test, run this under systemd or as a
# container that restarts automatically, e.g.:
#   docker run -d --name step-ca -p 9000:9000 \
#     -v "$STEP_PATH:/home/step" smallstep/step-ca
# or a systemd unit executing:
#   step-ca "$STEP_PATH/config/ca.json" --password-file "$WORKDIR/ca-password.txt"
echo ""
echo "Start the CA (foreground, for testing):"
echo "  step-ca $STEP_PATH/config/ca.json --password-file $WORKDIR/ca-password.txt"

# --- Step 4: extract the provisioner's private JWK for the registrar ---
# VERIFY THIS AGAINST YOUR STEP-CA VERSION -- the encrypted provisioner key
# lives inside ca.json as a JWE; the decrypt invocation below is the
# documented community pattern but has changed shape across releases.
KID=$(jq -r '.authority.provisioners[0].key.kid' "$STEP_PATH/config/ca.json")
jq -r '.authority.provisioners[0].encryptedKey' "$STEP_PATH/config/ca.json" \
  | step crypto jwe decrypt --password-file "$WORKDIR/provisioner-password.txt" \
  > "$WORKDIR/provisioner.priv.json"

echo ""
echo "Provisioner kid: $KID"
echo "  -> put this in config/shared.json's step_ca.provisioner_kid"
echo "Provisioner private JWK written to: $WORKDIR/provisioner.priv.json"
echo "  -> upload its CONTENTS into Password Safe:"
echo "       safe:   shared-infra"
echo "       secret: step-ca-provisioner-jwk"
echo "     (see app.load_step_ca_config() -- never commit this file)"
