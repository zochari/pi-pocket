// An upstream merge must not add a process launcher without a jail review. Entries are per source file, not per line.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const reviewed: Record<string, string> = {
    "src/launcher/access.ts":
        "server-internal, fixed command: cloudflared version probe and tunnel startup.",
    "src/launcher/main.ts":
        "server-internal, fixed command: starts Pocket's own Node server and opens its URL.",
    "src/server/background.ts":
        "jailed: model command argv uses jailed(); only the fixed log writer and split availability probe run outside.",
    "src/server/browser/cdp.ts":
        "server-internal, fixed command: Chromium infrastructure; executable and flags are server configuration, with a separate browser jail in the Nix deployment.",
    "src/server/git.ts": "jailed: git and repository-configured programs use jailed().",
    "src/server/github.ts": "jailed: gh uses jailed().",
    "src/server/jail.ts":
        "jailed: only this module constructs or extends NodeExecutionEnv, behind the tools policy.",
    "src/server/lock.ts": "server-internal, fixed command: getconf CLK_TCK probe.",
    "src/server/npm-install.ts":
        "server-internal, fixed command: npm root -g install-detection probe.",
    "src/server/npm-update.ts":
        "server-internal, fixed command: exact-version npm updater; package lifecycle scripts run unjailed; unused in the Nix deployment (read-only store package).",
    "src/server/reveal.ts":
        "server-internal, fixed command: platform-selected file-manager action; path passed as data, without a shell or conversation cwd.",
    "src/server/update-state.ts":
        "server-internal, fixed command: gitBytes and gitSync update/rollback the app checkout only; repo-configured filters and hooks run unjailed; unused in the Nix deployment (read-only store package).",
    "src/server/updates.ts":
        "server-internal, fixed command: npm ci for the app updater; package lifecycle scripts run unjailed; unused in the Nix deployment (read-only store package).",
};

function sources(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const path = join(dir, entry.name);

        return entry.isDirectory() ? sources(path) : /\.[cm]?[jt]s$/.test(path) ? [path] : [];
    });
}

// Module references plus bare process API calls: also review new calls in an already listed file.
// Updater code never runs in the read-only Nix deployment; its qualified file-level reviews above are sufficient.
const fileLevel = new Set([
    "src/server/npm-update.ts",
    "src/server/update-state.ts",
    "src/server/updates.ts",
]);
const reviewedCounts: Record<string, number> = {
    "src/launcher/access.ts": 3,
    "src/launcher/main.ts": 3,
    "src/server/background.ts": 3,
    "src/server/browser/cdp.ts": 2,
    "src/server/git.ts": 2,
    "src/server/github.ts": 2,
    "src/server/jail.ts": 2,
    "src/server/lock.ts": 2,
    "src/server/npm-install.ts": 2,
    "src/server/reveal.ts": 2,
};

function launcherCount(code: string, onEnvironment?: () => void): number {
    let count = 0;

    // Parse instead of matching text: comments, strings, RegExp.exec and method declarations are not spawn calls.
    // Module references catch aliases, namespace imports, require() and dynamic import() as well as named imports.
    function visit(node: ts.Node): void {
        // Imports and type references do not create an environment; value uses (including extends) can.
        const environment =
            ts.isIdentifier(node) &&
            node.text === "NodeExecutionEnv" &&
            !ts.isImportSpecifier(node.parent) &&
            !ts.isTypeReferenceNode(node.parent);

        if (environment) {
            onEnvironment?.();
        }

        if (
            ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
                /^(?:node:)?child_process$/.test(node.text)) ||
            environment ||
            (ts.isCallExpression(node) &&
                ts.isIdentifier(node.expression) &&
                /^(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)$/.test(
                    node.expression.text,
                ))
        ) {
            count++;
        }

        ts.forEachChild(node, visit);
    }

    visit(ts.createSourceFile("source.ts", code, ts.ScriptTarget.Latest, true));

    return count;
}

test("the spawn scanner finds imports and calls, not comments or unrelated methods", () => {
    for (const name of [
        "spawn",
        "spawnSync",
        "exec",
        "execSync",
        "execFile",
        "execFileSync",
        "fork",
    ]) {
        assert.ok(launcherCount(`${name}("command")`), name);
    }

    assert.ok(launcherCount('import { spawn as run } from "node:child_process"'));
    assert.ok(launcherCount('const cp = require("child_process"); cp.exec("command")'));
    assert.ok(launcherCount('await import("node:child_process")'));
    assert.ok(launcherCount("await import(`node:child_process`)"));
    assert.equal(launcherCount("new NodeExecutionEnv({ cwd })"), 1);
    assert.equal(launcherCount("class Custom extends NodeExecutionEnv {}"), 1);
    assert.equal(
        launcherCount('import { NodeExecutionEnv } from "env"; let env: NodeExecutionEnv;'),
        0,
    );
    assert.equal(launcherCount('/* spawn() */ "fork()"; /x/.exec("x"); class X { exec() {} }'), 0);
});

test("every process-spawn source file has a reviewed jail decision", () => {
    const root = fileURLToPath(new URL("../", import.meta.url));
    const found = ["src", "bin"]
        .flatMap((dir) => sources(join(root, dir)))
        .map(
            (path) =>
                [
                    relative(root, path).replaceAll("\\", "/"),
                    launcherCount(readFileSync(path, "utf8"), () => {
                        assert.equal(
                            path,
                            join(root, "src/server/jail.ts"),
                            "NodeExecutionEnv value uses must stay in src/server/jail.ts.",
                        );
                    }),
                ] as const,
        )
        .filter(([, count]) => count > 0);
    const files = found.map(([path]) => path).sort();
    const missing = files.filter((path) => reviewed[path] === undefined);

    assert.deepEqual(
        missing,
        [],
        `Unreviewed process spawn in ${missing.join(", ")}. Route it through the jail or add a justified entry to test/spawn-sites.test.ts.`,
    );
    assert.deepEqual(Object.keys(reviewed).sort(), files, "Remove stale spawn-review entries.");
    assert.deepEqual(
        Object.fromEntries(found.filter(([path]) => !fileLevel.has(path))),
        reviewedCounts,
        "Process-spawn sites changed. Route new sites through the jail or add a justified review entry and update reviewedCounts.",
    );

    for (const reason of Object.values(reviewed)) {
        assert.match(reason, /^(jailed|server-internal, fixed command): .+/);
    }
});
