// A test double for the deployment-owned jail launcher: the --chdir/--setenv/-- argv contract, an empty environment,
// and, when available, bubblewrap with the deployment's private PID namespace and hidden server data folder.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const policy = JSON.parse(readFileSync(process.env.PI_POCKET_TOOLS_POLICY!, "utf8")) as {
    bwrap?: string;
    file_deny: string[];
};
const args = process.argv.slice(2);
const env: Record<string, string> = { PATH: process.env.PATH!, PI_POCKET_JAILED: "1" };
let cwd = process.cwd();
let index = 0;

while (args[index] !== "--") {
    const flag = args[index++];

    if (flag === "--chdir") {
        cwd = args[index++]!;
    } else if (flag === "--setenv") {
        const name = args[index++]!;

        env[name] = args[index++]!;
    } else {
        throw new Error(`Unexpected jail launcher argument: ${flag}`);
    }
}

const command = args.slice(index + 1);
const bwrap = policy.bwrap;
const jailed =
    bwrap === undefined
        ? command
        : [
              bwrap,
              "--unshare-user",
              "--unshare-ipc",
              "--unshare-uts",
              "--unshare-cgroup-try",
              "--new-session",
              "--die-with-parent",
              "--ro-bind",
              "/",
              "/",
              "--dev",
              "/dev",
              "--unshare-pid",
              "--proc",
              "/proc",
              "--bind",
              cwd,
              cwd,
              ...policy.file_deny.flatMap((path) => ["--tmpfs", path, "--remount-ro", path]),
              "--chdir",
              cwd,
              "--",
              ...command,
          ];
const result = spawnSync(jailed[0]!, jailed.slice(1), { cwd, env, stdio: "inherit" });

process.exit(result.status ?? 125);
