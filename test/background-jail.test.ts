// The background command goes through the tools jail, but the fixed log writer keeps access to the server folder.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
    chmodSync,
    existsSync,
    mkdirSync,
    mkdtempSync,
    readdirSync,
    readFileSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

const skip = existsSync("/proc/self/stat") ? false : "background tasks need /proc";
const probe = spawnSync("bwrap", [
    "--unshare-user",
    "--unshare-pid",
    "--ro-bind",
    "/",
    "/",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--",
    "true",
]);
const noBwrap = probe.status === 0 ? false : "bubblewrap or user namespaces unavailable";

if (process.env.PI_POCKET_REQUIRE_JAIL_TESTS === "1" && (skip || noBwrap)) {
    throw new Error(
        "PI_POCKET_REQUIRE_JAIL_TESTS=1 requires bubblewrap and working user namespaces.",
    );
}

const root = mkdtempSync(join(tmpdir(), "pocket-background-jail-"));
const data = join(root, "data");
const launcher = join(root, "jail-exec");
const previousPolicy = process.env.PI_POCKET_TOOLS_POLICY;
const previousSecret = process.env.POCKET_JAIL_TEST_SECRET;
const policy = { jail_exec: launcher, file_deny: [data], file_allow: [] };

function usePolicy(name: string, bwrap = false): void {
    const file = join(root, `${name}.policy.json`);

    writeFileSync(file, JSON.stringify({ ...policy, ...(bwrap ? { bwrap: "bwrap" } : {}) }));
    process.env.PI_POCKET_TOOLS_POLICY = file;
}

mkdirSync(data);
writeFileSync(join(data, "secret"), "denied-file-secret");
writeFileSync(
    launcher,
    `#!${process.execPath}\nimport ${JSON.stringify(fileURLToPath(new URL("./jail-launcher.ts", import.meta.url)))};\n`,
);
chmodSync(launcher, 0o755);
usePolicy("startup");
Reflect.set(process.env, "POCKET_JAIL_TEST_SECRET", ["server", "only", "secret"].join("-"));

// Set the policy before the app (and its cached policy) is imported.
const { cleanUp, newSession, openApp, scriptedModel, until } = await import("./helpers.ts");
const model = scriptedModel();
let app = await openApp(model, data);

app.background.timing = { look: 50, grace: 400, starting: 300, sweep: 60_000 };

const sessions = new Set<Parameters<typeof app.background.list>[0]>();

function alive(pid: number): boolean {
    try {
        return !/\) [ZX] /.test(readFileSync(`/proc/${pid}/stat`, "utf8"));
    } catch {
        return false;
    }
}

/** Host PIDs, including children inside the private PID namespace. */
function descendants(pid: number): number[] {
    const children = readdirSync("/proc")
        .filter((name) => /^\d+$/.test(name))
        .flatMap((name) => {
            try {
                const text = readFileSync(`/proc/${name}/stat`, "utf8");
                const fields = text.slice(text.lastIndexOf(")") + 2).split(" ");

                return fields[0] === "Z" ? [] : [{ pid: Number(name), parent: Number(fields[1]) }];
            } catch {
                return [];
            }
        });
    const found = new Set([pid]);
    let size = 0;

    while (size !== found.size) {
        size = found.size;

        for (const child of children) {
            if (found.has(child.parent)) {
                found.add(child.pid);
            }
        }
    }

    return [...found];
}

async function session() {
    const id = await newSession(app);

    sessions.add(id);

    return id;
}

async function ended(id: Awaited<ReturnType<typeof session>>, taskId: string) {
    await until(
        async () =>
            (await app.background.list(id)).find((item) => item.id === taskId)?.status === "exited",
        "the jailed task to exit",
    );

    return (await app.background.list(id)).find((item) => item.id === taskId)!;
}

after(async () => {
    for (const id of sessions) {
        for (const item of await app.background.list(id)) {
            await app.background.stop(id, item.id);
        }
    }

    await app.close();
    cleanUp();
    rmSync(root, { recursive: true, force: true });

    if (previousPolicy === undefined) {
        delete process.env.PI_POCKET_TOOLS_POLICY;
    } else {
        process.env.PI_POCKET_TOOLS_POLICY = previousPolicy;
    }

    if (previousSecret === undefined) {
        delete process.env.POCKET_JAIL_TEST_SECRET;
    } else {
        Reflect.set(process.env, "POCKET_JAIL_TEST_SECRET", previousSecret);
    }
});

test(
    "background uses the jail launcher and explicit additions, not the server environment",
    { skip },
    async () => {
        usePolicy("environment");

        const remove = app.commandEnvs.add(() => ({ POCKET_BACKGROUND_ADDED: "explicit" }));

        try {
            const id = await session();
            const task = await app.background.start(id, {
                command:
                    'printf "%s:%s:%s:%s\\n" "$PI_POCKET_JAILED" "${POCKET_JAIL_TEST_SECRET-unset}" "$POCKET_BACKGROUND_ADDED" "$PI_POCKET_BACKGROUND"; exit 7',
                notify: false,
            });
            const result = await ended(id, task.id);

            assert.equal(result.code, 7);
            assert.match(
                (await app.background.read(id, task.id))!.text,
                new RegExp(`1:unset:explicit:${data}#${String(id)}/${task.id}`),
            );
            assert.equal(
                readFileSync(join(data, "background", String(id), `${task.id}.exit`), "utf8"),
                "7 0",
            );
        } finally {
            remove();
        }
    },
);

test("command substitutions and option-like text stay on the jailed side", { skip }, async () => {
    usePolicy("command-text");

    const id = await session();
    const literal = "--setenv POCKET_JAIL_TEST_SECRET bypass; $(echo OUTER)";
    const task = await app.background.start(id, {
        command: `printf 'scope:%s:%s\\n' "$(printf %s \"$PI_POCKET_JAILED\")" "$(printf %s \"\${POCKET_JAIL_TEST_SECRET-unset}\")"; printf '%s\\n' '${literal}'; test -z "\${PI_POCKET_BACKGROUND_COMMAND-}" || exit 1; exit 19`,
        notify: false,
    });
    const result = await ended(id, task.id);

    assert.equal(result.code, 19);
    assert.equal((await app.background.read(id, task.id))!.text, `scope:1:unset\n${literal}\n`);
});

test(
    "a background command cannot read server secrets, denied files, or the server's /proc environment",
    { skip: skip || noBwrap },
    async () => {
        usePolicy("denied", true);

        const id = await session();
        const task = await app.background.start(id, {
            command: `test -z "\${POCKET_JAIL_TEST_SECRET-}" || exit 1; if cat ${JSON.stringify(join(data, "secret"))}; then exit 2; fi; if cat /proc/${process.pid}/environ >/dev/null 2>&1; then exit 3; fi; echo DENIED; exit 23`,
            notify: false,
        });
        const result = await ended(id, task.id);
        const text = (await app.background.read(id, task.id))!.text;

        assert.equal(result.code, 23);
        assert.match(text, /DENIED/);
        assert.doesNotMatch(text, /denied-file-secret|server-only-secret/);
        assert.equal(
            readFileSync(join(data, "background", String(id), `${task.id}.exit`), "utf8"),
            "23 0",
        );
    },
);

test(
    "a jailed task keeps its detached wrapper across restart, and stops its private process tree",
    { skip: skip || noBwrap },
    async () => {
        usePolicy("restart", true);

        const id = await session();
        const task = await app.background.start(id, {
            command: "echo ready; bash -c 'trap \"\" TERM; sleep 300' & wait",
            notify: false,
        });

        await until(
            async () => (await app.background.read(id, task.id))!.text.includes("ready"),
            "the jailed command to start",
        );
        assert.equal(
            readFileSync(`/proc/${task.pid}/stat`, "utf8")
                .slice(readFileSync(`/proc/${task.pid}/stat`, "utf8").lastIndexOf(")") + 2)
                .split(" ")[2],
            String(task.pid),
        );
        assert.ok(
            readFileSync(`/proc/${task.pid}/environ`, "utf8").includes(
                `PI_POCKET_BACKGROUND=${data}#${String(id)}/${task.id}`,
            ),
        );

        const tree = descendants(task.pid);

        assert.ok(tree.length >= 5, "the wrapper, launcher, jail and command children are running");
        await app.close();
        app = await openApp(model, data);
        app.background.timing = { look: 50, grace: 400, starting: 300, sweep: 60_000 };
        assert.equal((await app.background.list(id))[0]!.status, "running");
        assert.equal((await app.background.stop(id, task.id))!.status, "stopped");
        await until(
            () => tree.every((pid) => !alive(pid)),
            "the detached wrapper and its jailed process tree to stop",
        );
    },
);

test(
    "the private PID namespace removes daemons when the command exits",
    { skip: skip || noBwrap },
    async () => {
        usePolicy("daemon", true);

        const id = await session();
        const gate = join(app.cwdOf(id), "release-jailed-daemon");
        const task = await app.background.start(id, {
            command: `setsid sleep 300 >/dev/null 2>&1 </dev/null & echo ready; while [ ! -f ${JSON.stringify(gate)} ]; do sleep 0.05; done`,
            notify: false,
        });

        await until(
            async () => (await app.background.read(id, task.id))!.text.includes("ready"),
            "the daemon to start",
        );
        const tree = descendants(task.pid);

        assert.ok(tree.length >= 5);
        writeFileSync(gate, "");
        const result = await ended(id, task.id);

        assert.equal(result.code, 0);
        assert.equal(result.left, undefined, "a daemon cannot outlive its PID namespace");
        await until(() => tree.every((pid) => !alive(pid)), "all of the private namespace to end");
    },
);
