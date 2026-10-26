// The tools jail deployment patch (src/server/jail.ts): commands go through the policy's jail program, and the file
// methods refuse denied paths, also through symbolic links.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { BACKGROUND_CONTEXT } from "@earendil-works/chord/context";
import { JailExecutionEnv, jailed } from "../src/server/jail.ts";

function setup() {
    const root = mkdtempSync(join(tmpdir(), "pocket-jail-"));
    const fake = join(root, "jail-exec");

    // Stands in for pi-pocket-jail-exec: marks its output, then runs what follows `--`.
    writeFileSync(
        fake,
        '#!/bin/sh\nwhile [ "$1" != -- ]; do shift; done\nshift\necho JAILED\nexec "$@"\n',
    );
    chmodSync(fake, 0o755);
    mkdirSync(join(root, "data", "worktrees"), { recursive: true });
    mkdirSync(join(root, "lane"));
    writeFileSync(join(root, "data", "config.json"), "owner token");
    writeFileSync(join(root, "data", "worktrees", "file"), "work");
    symlinkSync(join(root, "data", "config.json"), join(root, "lane", "link"));

    const policy = {
        jail_exec: fake,
        file_deny: [join(root, "data")],
        file_allow: [join(root, "data", "worktrees")],
    };

    return { root, policy, env: new JailExecutionEnv(join(root, "lane"), policy) };
}

test("commands run through the jail program, with the caller's variables as --setenv", async () => {
    const { env } = setup();
    let output = "";
    const result = await env.exec(
        "echo hi",
        { onOutput: (text) => (output += text) },
        BACKGROUND_CONTEXT,
    );

    assert.ok(result.ok);
    assert.equal(output, "JAILED\nhi\n");
    assert.deepEqual(
        jailed({ jail_exec: "/j", file_deny: [], file_allow: [] }, "/w", ["git"], { A: "1" }),
        {
            file: "/j",
            args: ["--chdir", "/w", "--setenv", "A", "1", "--", "git"],
        },
    );
});

test("file methods refuse denied paths, also through links, and allow the exceptions", async () => {
    const { root, env } = setup();

    for (const path of [
        join(root, "data", "config.json"),
        join(root, "lane", "link"),
        join(root, "data", "new"),
    ]) {
        const read = await env.readTextFile(path, BACKGROUND_CONTEXT);

        assert.ok(!read.ok && read.error.code === "permission_denied", path);
    }

    const written = await env.writeFile(join(root, "data", "new"), "x", BACKGROUND_CONTEXT);

    assert.ok(!written.ok);

    const allowed = await env.readTextFile(
        join(root, "data", "worktrees", "file"),
        BACKGROUND_CONTEXT,
    );

    assert.ok(allowed.ok && allowed.value === "work");
    assert.ok((await env.writeFile("ok.txt", "x", BACKGROUND_CONTEXT)).ok);
});
