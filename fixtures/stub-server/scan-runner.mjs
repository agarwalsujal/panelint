#!/usr/bin/env node
/**
 * Runs a real `acquireStdio()` in its own process, so a test can interrupt it.
 *
 * The teardown guarantee under test — SIGINT reaching Panelint kills the
 * spawned server's whole process group — cannot be exercised inside the test
 * runner, because the handler ends by re-raising the signal at the default
 * disposition. So the scan runs here instead, and the test signals this
 * process.
 *
 * Usage:  node scan-runner.mjs <compiled-src-dir> <stub-path> <mode> <pidfile>
 */

const [distDir, stubPath, mode, pidfile] = process.argv.slice(2);

const { acquireStdio } = await import(new URL('acquire/stdio.js', `file://${distDir}/`).href);

const set = await acquireStdio({
  command: process.execPath,
  args: [stubPath, mode, pidfile],
  allowSpawn: true,
  requestTimeoutMs: 30_000,
  totalDeadlineMs: 60_000,
});

// Only reached if the scan is not interrupted.
process.stdout.write(`DONE ${set.resources.length}\n`);
