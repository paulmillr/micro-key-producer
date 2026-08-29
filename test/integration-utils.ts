import { describe, it } from '@paulmillr/jsbt/test.js';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Shared scaffolding for integration tests (test/integration.ts) that shell out
// to local command-line tools: probes, per-test temp dirs, gpg-agent lifecycle.

export type ToolProbe = { ok: true } | { ok: false; reason: string };

// `--agent` opts into private-key/passphrase checks that need a live gpg-agent.
export const RUN_AGENT = process.argv.includes('--agent');

export const toolProbe = (
  cmd: string,
  args: string[],
  opts: { ignoreStatus?: boolean; parseReason?: (output: string) => string } = {}
): ToolProbe => {
  const res = spawnSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (res.error) return { ok: false, reason: res.error.message };
  if (!opts.ignoreStatus && res.status !== 0) {
    const output = res.stderr || res.stdout || '';
    const reason = opts.parseReason
      ? opts.parseReason(output)
      : output.trim() || `${cmd} exited with status ${res.status}`;
    return { ok: false, reason };
  }
  return { ok: true };
};

export const describeIfTool =
  (probe: ToolProbe, requirement: string) =>
  (message: string, suite: () => void): void => {
    if (probe.ok) describe(message, suite);
    else it.skip(`${message} (requires ${requirement}: ${probe.reason})`, () => {});
  };

export const tmpDir = <T>(
  prefix: string,
  fn: (dir: string) => T,
  onCleanup?: (dir: string) => void
): T => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(dir, 0o700);
  try {
    return fn(dir);
  } finally {
    if (onCleanup) onCleanup(dir);
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

export const launchGpgAgent = (
  homedir: string,
  opts: { env?: NodeJS.ProcessEnv; parseReason?: (output: string) => string } = {}
): void => {
  const res = spawnSync('gpgconf', ['--homedir', homedir, '--launch', 'gpg-agent'], {
    encoding: 'utf8',
    env: opts.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    const output = res.stderr || res.stdout || '';
    throw new Error(
      opts.parseReason ? opts.parseReason(output) : output.trim() || 'gpg-agent launch failed'
    );
  }
};

export const killGpgAgent = (homedir: string): void => {
  spawnSync('gpgconf', ['--homedir', homedir, '--kill', 'gpg-agent'], { stdio: 'ignore' });
};
