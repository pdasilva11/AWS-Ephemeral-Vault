const { core, fs, path, DIR, sensor } = require("./common");
const { DefaultArtifactClient } = require("@actions/artifact");

async function run() {
  if (core.getState("started") !== "1") return;
  sensor("stop");
  // the sensor runs as root; make its files readable for the upload
  require("child_process").spawnSync("sudo", ["chmod", "-R", "a+rX", DIR]);
  const files = ["summary.json", "events.jsonl", "sensor.log"].map((f) => path.join(DIR, f)).filter((f) => fs.existsSync(f));
  if (!files.length) return core.warning("attrib-sensor recorded nothing to upload.");
  const name = core.getInput("artifact-name") || "attrib-sensor";
  const job = process.env.GITHUB_JOB || "job";
  const client = new DefaultArtifactClient();
  await client.uploadArtifact(`${name}-${job}`, files, DIR, {
    retentionDays: parseInt(core.getInput("retention-days") || "30", 10),
  });
  core.info(`attrib-sensor: uploaded ${files.length} files as ${name}-${job}`);
}

run().catch((e) => core.warning(`attrib-sensor post step: ${e.message}`));
