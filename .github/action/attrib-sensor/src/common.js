// Shared by main (start the sensor) and post (stop it, upload what it recorded).
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const core = require("@actions/core");

const SENSOR = path.join(__dirname, "..", "sensor.py");
const DIR = path.join(process.env.RUNNER_TEMP || "/tmp", "attrib-sensor");

function supported() {
  if (process.platform !== "linux") {
    core.warning(`attrib-sensor: ${process.platform} runners aren't supported yet; the job runs unmonitored.`);
    return false;
  }
  const sudo = spawnSync("sudo", ["-n", "true"]);
  if (sudo.status !== 0) {
    core.warning("attrib-sensor: needs passwordless sudo; the job runs unmonitored.");
    return false;
  }
  return true;
}

function env() {
  const allowed = core.getInput("allowed-endpoints");
  const e = {
    ...process.env,
    ATTRIB_DIR: DIR,
    ATTRIB_MODE: (core.getInput("egress-policy") || "audit").toLowerCase(),
    ATTRIB_ALLOWED: allowed,
    ATTRIB_CONSOLE_URL: core.getInput("console-url"),
    ATTRIB_INGEST_TOKEN: core.getInput("ingest-token"),
  };
  if (e.ATTRIB_INGEST_TOKEN) core.setSecret(e.ATTRIB_INGEST_TOKEN);
  return e;
}

function sensor(cmd) {
  // sudo -E keeps GITHUB_* and ATTRIB_* variables; the sensor itself never prints secrets
  return spawnSync("sudo", ["-E", "python3", SENSOR, cmd], { stdio: "inherit", env: env() });
}

module.exports = { core, fs, path, DIR, supported, sensor };
