import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const packageRoot = fileURLToPath(new URL("../", import.meta.url));
const generatorPath = fileURLToPath(
  new URL("./generate-wire.mjs", import.meta.url),
);
const expectedDirectory = `${packageRoot}/src/generated`;
const temporaryRoot = await mkdtemp(join(tmpdir(), "conduit-wire-"));
const actualDirectory = join(temporaryRoot, "generated");

try {
  await execute(process.execPath, [generatorPath, actualDirectory]);

  const expectedFiles = await listFiles(expectedDirectory);
  const actualFiles = await listFiles(actualDirectory);
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new TypeError(
      `generated wire file list differs\nexpected: ${expectedFiles.join(", ")}\nactual: ${actualFiles.join(", ")}`,
    );
  }

  for (const relativePath of expectedFiles) {
    const [expected, actual] = await Promise.all([
      readFile(join(expectedDirectory, relativePath)),
      readFile(join(actualDirectory, relativePath)),
    ]);
    if (!expected.equals(actual)) {
      throw new TypeError(`generated wire file is stale: ${relativePath}`);
    }
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function listFiles(root, relativeDirectory = "") {
  const directory = join(root, relativeDirectory);
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const relativePath = join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(root, relativePath)));
    } else if (entry.isFile()) {
      files.push(relativePath);
    }
  }
  return files.sort();
}
