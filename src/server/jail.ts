/**
 * The tools jail, a deployment patch (not upstream Pi Pocket). When PI_POCKET_TOOLS_POLICY names a policy file, every
 * command Pi Pocket runs for a conversation (Pi's bash tool, `!` commands, goal checks) and for itself (git, gh) starts
 * through the policy's `jail_exec` program, which runs it in bubblewrap with an allowlisted environment, and the
 * conversation's file methods refuse the paths the policy denies (the server's database, owner token, and sign-ins).
 * Without the variable, Pi Pocket runs as upstream does. A variable that names a missing or malformed file throws, so a
 * broken deployment runs nothing rather than running it unjailed.
 */
import { readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import type { Context } from "@earendil-works/chord";
import {
    type BinaryReader,
    type DirReader,
    err,
    ExecutionError,
    FileError,
    type FileInfo,
    type FileWatcher,
    type Result,
    type ShellExecOptions,
    type ShellExecResult,
    type TextLineReader,
    type WatchChange,
    type WatchTarget,
} from "@earendil-works/pi-durable/env";
import { NodeExecutionEnv } from "@earendil-works/pi-durable/env/node";

export type JailPolicy = {
    /** The program that runs `-- argv...` in the jail. */
    jail_exec: string;
    /** Paths the file methods refuse, with everything below them... */
    file_deny: string[];
    /** ...except these, and everything below them. */
    file_allow: string[];
};

let loaded: JailPolicy | null | undefined;

/** The deployment's policy, or null when it sets none. Read once. */
export function jailPolicy(): JailPolicy | null {
    if (loaded !== undefined) {
        return loaded;
    }

    const file = process.env.PI_POCKET_TOOLS_POLICY;

    if (file === undefined || file === "") {
        loaded = null;

        return loaded;
    }

    const policy = JSON.parse(readFileSync(file, "utf8")) as Partial<JailPolicy>;

    if (
        typeof policy.jail_exec !== "string" ||
        !Array.isArray(policy.file_deny) ||
        !Array.isArray(policy.file_allow)
    ) {
        throw new Error(
            `${file} is not a tools jail policy: it needs jail_exec, file_deny and file_allow.`,
        );
    }

    loaded = policy as JailPolicy;

    return loaded;
}

/** The program and arguments that run `argv` in the jail, in `cwd` (the policy's default when undefined). */
export function jailed(
    policy: JailPolicy,
    cwd: string | undefined,
    argv: readonly string[],
    env: Record<string, string> = {},
): { file: string; args: string[] } {
    const args = cwd === undefined ? [] : ["--chdir", cwd];

    for (const [name, value] of Object.entries(env)) {
        args.push("--setenv", name, value);
    }

    return { file: policy.jail_exec, args: [...args, "--", ...argv] };
}

function under(path: string, root: string): boolean {
    return path === root || path.startsWith(root.endsWith(sep) ? root : root + sep);
}

/** `path` with every symbolic link resolved, as far as it exists; the missing rest is appended as written. */
function real(path: string): string {
    const missing: string[] = [];
    let at = path;

    for (;;) {
        try {
            return join(realpathSync(at), ...missing.reverse());
        } catch {
            const parent = dirname(at);

            if (parent === at) {
                return path;
            }

            missing.push(basename(at));
            at = parent;
        }
    }
}

/**
 * Pi Durable's local environment with its commands jailed and its file methods fenced. File methods stay in this
 * process (they run no program), so the fence checks the path as written and as resolved through symbolic links: a
 * link a jailed command plants in a project folder does not reach the server's files. A link swapped between the check
 * and the access still could; the jail, which hides those files from commands, is the boundary.
 */
export class JailExecutionEnv extends NodeExecutionEnv {
    readonly #policy: JailPolicy;

    constructor(cwd: string, policy: JailPolicy) {
        super({ cwd });
        this.#policy = policy;
    }

    #denied(path: string): boolean {
        const literal = resolve(path);

        return [literal, real(literal)].some(
            (each) =>
                this.#policy.file_deny.some((root) => under(each, root)) &&
                !this.#policy.file_allow.some((root) => under(each, root)),
        );
    }

    /** A refusal when any of `paths` is denied, else undefined. */
    async #fence<T>(paths: string[], context: Context): Promise<Result<T, FileError> | undefined> {
        for (const path of paths) {
            const absolute = await this.absolutePath(path, context);

            if (!absolute.ok) {
                return err(absolute.error);
            }

            if (this.#denied(absolute.value)) {
                return err(
                    new FileError(
                        "permission_denied",
                        `${absolute.value} belongs to Pi Pocket itself.`,
                        absolute.value,
                    ),
                );
            }
        }

        return undefined;
    }

    override async exec(
        command: string | readonly string[],
        options: ShellExecOptions | undefined,
        context: Context,
    ): Promise<Result<ShellExecResult, ExecutionError>> {
        const cwd = await this.absolutePath(options?.cwd ?? this.cwd, context);

        if (!cwd.ok) {
            return err(new ExecutionError("spawn_error", cwd.error.message, cwd.error));
        }

        const argv = typeof command === "string" ? ["bash", "-c", command] : [...command];

        if (argv.length === 0) {
            return err(new ExecutionError("spawn_error", "Empty argv: no program to run"));
        }

        // The jail program reads the allowlist from its own environment; only the caller's explicit variables are added.
        const { env, inheritEnv: _inherit, ...rest } = options ?? {};
        const run = jailed(this.#policy, cwd.value, argv, env);

        return super.exec([run.file, ...run.args], { ...rest, cwd: cwd.value }, context);
    }

    override async watch(
        targets: readonly WatchTarget[],
        onChange: (change: WatchChange) => void,
        context: Context,
    ): Promise<Result<FileWatcher, FileError>> {
        return (
            (await this.#fence<FileWatcher>(
                targets.map((target) => target.path),
                context,
            )) ?? super.watch(targets, onChange, context)
        );
    }

    override async readTextFile(
        path: string,
        context: Context,
    ): Promise<Result<string, FileError>> {
        return (await this.#fence<string>([path], context)) ?? super.readTextFile(path, context);
    }

    override async openTextLineReader(
        path: string,
        context: Context,
    ): Promise<Result<TextLineReader, FileError>> {
        return (
            (await this.#fence<TextLineReader>([path], context)) ??
            super.openTextLineReader(path, context)
        );
    }

    override async readTextLines(
        path: string,
        options: { maxLines?: number } | undefined,
        context: Context,
    ): Promise<Result<string[], FileError>> {
        return (
            (await this.#fence<string[]>([path], context)) ??
            super.readTextLines(path, options, context)
        );
    }

    override async readBinaryFile(
        path: string,
        context: Context,
    ): Promise<Result<Uint8Array, FileError>> {
        return (
            (await this.#fence<Uint8Array>([path], context)) ?? super.readBinaryFile(path, context)
        );
    }

    override async openBinaryReader(
        path: string,
        options: { noFollow?: boolean } | undefined,
        context: Context,
    ): Promise<Result<BinaryReader, FileError>> {
        return (
            (await this.#fence<BinaryReader>([path], context)) ??
            super.openBinaryReader(path, options, context)
        );
    }

    override async writeFile(
        path: string,
        content: string | Uint8Array,
        context: Context,
    ): Promise<Result<void, FileError>> {
        return (
            (await this.#fence<void>([path], context)) ?? super.writeFile(path, content, context)
        );
    }

    override async appendFile(
        path: string,
        content: string | Uint8Array,
        context: Context,
    ): Promise<Result<void, FileError>> {
        return (
            (await this.#fence<void>([path], context)) ?? super.appendFile(path, content, context)
        );
    }

    override async truncateFile(
        path: string,
        size: number,
        context: Context,
    ): Promise<Result<void, FileError>> {
        return (
            (await this.#fence<void>([path], context)) ?? super.truncateFile(path, size, context)
        );
    }

    override async flushFile(path: string, context: Context): Promise<Result<void, FileError>> {
        return (await this.#fence<void>([path], context)) ?? super.flushFile(path, context);
    }

    override async renameFile(
        sourcePath: string,
        destinationPath: string,
        context: Context,
    ): Promise<Result<void, FileError>> {
        return (
            (await this.#fence<void>([sourcePath, destinationPath], context)) ??
            super.renameFile(sourcePath, destinationPath, context)
        );
    }

    override async fileInfo(path: string, context: Context): Promise<Result<FileInfo, FileError>> {
        return (await this.#fence<FileInfo>([path], context)) ?? super.fileInfo(path, context);
    }

    override async listDir(path: string, context: Context): Promise<Result<FileInfo[], FileError>> {
        return (await this.#fence<FileInfo[]>([path], context)) ?? super.listDir(path, context);
    }

    override async openDirReader(
        path: string,
        context: Context,
    ): Promise<Result<DirReader, FileError>> {
        return (
            (await this.#fence<DirReader>([path], context)) ?? super.openDirReader(path, context)
        );
    }

    override async canonicalPath(
        path: string,
        context: Context,
    ): Promise<Result<string, FileError>> {
        return (await this.#fence<string>([path], context)) ?? super.canonicalPath(path, context);
    }

    override async exists(path: string, context: Context): Promise<Result<boolean, FileError>> {
        return (await this.#fence<boolean>([path], context)) ?? super.exists(path, context);
    }

    override async createDir(
        path: string,
        options: { recursive?: boolean } | undefined,
        context: Context,
    ): Promise<Result<void, FileError>> {
        return (
            (await this.#fence<void>([path], context)) ?? super.createDir(path, options, context)
        );
    }

    override async remove(
        path: string,
        options: { recursive?: boolean; force?: boolean } | undefined,
        context: Context,
    ): Promise<Result<void, FileError>> {
        return (await this.#fence<void>([path], context)) ?? super.remove(path, options, context);
    }
}

/** Where a conversation's commands run: jailed when the deployment sets a policy, else on this machine. */
export function localEnv(cwd: string): NodeExecutionEnv {
    const policy = jailPolicy();

    return policy === null ? new NodeExecutionEnv({ cwd }) : new JailExecutionEnv(cwd, policy);
}
