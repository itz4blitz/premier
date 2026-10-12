// Runs the examples of the documentation through the real recorder and the
// real validator: each one is recorded with `premier record` and must verify
// with no semantic diagnostic. An example that would trip the validator (a
// result with no link to its spawn, an event without a payload) fails here
// instead of in a reader's trace.
//
// Needs a built `premier` binary: PREMIER_BIN, or target/debug/premier under
// CARGO_TARGET_DIR or the repository root. Without one the examples are
// skipped, unless PREMIER_REQUIRE_CLI=1 (set in CI) makes that a failure.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..", "..");
const sdkEntry = pathToFileURL(resolve(here, "..", "dist", "index.js")).href;
const SDK_EXPORTS = "emit, premier, isPremierActive, flush, span, childOf, newId, premierStats";

function findBinary() {
  const candidates = [
    process.env.PREMIER_BIN,
    process.env.CARGO_TARGET_DIR && join(process.env.CARGO_TARGET_DIR, "debug", "premier"),
    join(root, "target", "debug", "premier"),
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate));
}

/** Fenced code blocks of a Markdown file: `{ language, code, line }`. */
function codeBlocks(file) {
  const blocks = [];
  let open = null;
  readFileSync(file, "utf8")
    .split("\n")
    .forEach((text, index) => {
      const fence = text.match(/^```(\w*)\s*$/);
      if (!fence) {
        if (open) open.lines.push(text);
      } else if (open) {
        blocks.push({ language: open.language, code: open.lines.join("\n"), line: open.line });
        open = null;
      } else {
        open = { language: fence[1], lines: [], line: index + 2 };
      }
    });
  return blocks;
}

/** The examples of one file that emit events: SDK modules and `premier emit` scripts. */
function examples(file) {
  return codeBlocks(file).flatMap((block) => {
    const isModule =
      ["ts", "js", "mjs"].includes(block.language) && /\b(premier\.|emit\(|span\()/.test(block.code);
    const isShell =
      ["sh", "bash"].includes(block.language) &&
      /^\s*(\w+="\$\()?premier emit\b/m.test(block.code) &&
      !/\$ premier/.test(block.code);
    if (isModule) return [{ ...block, type: "module" }];
    if (isShell) return [{ ...block, type: "shell" }];
    return [];
  });
}

const binary = findBinary();
const required = process.env.PREMIER_REQUIRE_CLI === "1";
const skip = binary || required ? false : "no built premier binary (set PREMIER_BIN to run the documentation examples)";

function record(example, work) {
  const trace = join(work, "example.atrace");
  let command;
  if (example.type === "module") {
    // The examples import the package by name; here that is the built SDK.
    let code = example.code.replaceAll('"@premierstudio/trace"', JSON.stringify(sdkEntry));
    if (!code.includes(sdkEntry)) code = `import { ${SDK_EXPORTS} } from ${JSON.stringify(sdkEntry)};\n${code}`;
    const script = join(work, "example.mjs");
    writeFileSync(script, code);
    command = [process.execPath, script];
  } else {
    const script = join(work, "example.sh");
    writeFileSync(script, `set -eu\n${example.code}\n`);
    command = ["sh", script];
  }
  const recorded = spawnSync(binary, ["record", "--output", trace, "--", ...command], {
    cwd: work,
    encoding: "utf8",
    // `premier emit` in a shell example is this binary.
    env: { ...process.env, PATH: `${dirname(binary)}${delimiter}${process.env.PATH}` },
  });
  assert.equal(recorded.status, 0, `the example failed under premier record:\n${recorded.stdout}\n${recorded.stderr}`);
  return trace;
}

const documents = [
  { file: resolve(here, "..", "README.md"), atLeast: 7 },
  { file: join(root, "README.md"), atLeast: 1 },
  { file: join(root, "docs", "collector.md"), atLeast: 1 },
  { file: join(root, "docs", "cli.md"), atLeast: 1 },
];

for (const { file, atLeast } of documents) {
  const name = file.slice(root.length + 1);
  const found = examples(file);

  test(`${name} still contains the examples this test runs`, () => {
    assert.ok(found.length >= atLeast, `expected at least ${atLeast} runnable examples in ${name}, found ${found.length}`);
  });

  for (const example of found) {
    // An example piping through jq needs jq; only CI insists on having it.
    const needsJq = example.type === "shell" && /\bjq\b/.test(example.code);
    const hasJq = !needsJq || spawnSync("jq", ["--version"]).status === 0;
    const skipExample = skip || (hasJq || required ? false : "jq is not installed");
    test(`${name}:${example.line} (${example.type}) records events that verify with no diagnostics`, { skip: skipExample }, () => {
      assert.ok(binary, "PREMIER_REQUIRE_CLI=1 but no premier binary was found; build it or set PREMIER_BIN");
      const work = mkdtempSync(join(tmpdir(), "premier-readme-"));
      try {
        const trace = record(example, work);
        const report = execFileSync(binary, ["verify", trace], { encoding: "utf8" });
        const events = Number(report.match(/\((\d+) events/)?.[1] ?? 0);
        // process.start and process.exit are the recorder's own two events.
        assert.ok(events > 2, `the example emitted no events:\n${report}`);
        assert.match(report, /, 0 semantic diagnostics\)/, `the example trips the validator:\n${report}`);
      } finally {
        rmSync(work, { recursive: true, force: true });
      }
    });
  }
}
