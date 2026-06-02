import { cfb } from '@noble/ciphers/aes.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { numberToBytesBE } from '@noble/curves/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { md5 } from '@noble/hashes/legacy.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { base64, hex, utf8 } from '@scure/base';
import { execFileSync, spawnSync } from 'node:child_process';
import { deepStrictEqual, throws } from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as pgp from '../src/pgp.ts';

// Run directly; this is intentionally not imported by test/index.ts because it needs local GnuPG.
// Public-key checks run with --no-autostart; GnuPG 2.x still routes private-key/passphrase
// operations through gpg-agent, so those checks use a temporary homedir and kill the agent on cleanup.
type SecretKey = Parameters<typeof pgp.decodeSecretKey>[1];
type GPGProbe = { ok: true } | { ok: false; reason: string };
const secretKeyPacket = (packets: pgp.Packet[]): SecretKey => {
  const packet = packets.find((p): p is Extract<pgp.Packet, { TAG: 'secretKey' }> => {
    return p.TAG === 'secretKey';
  });
  if (!packet) throw new Error('missing secret-key packet');
  return packet.data;
};
const GPG_TIME = '1234567890';
const seed = hex.decode('29f47c314ee8b1c77a0b7e4c0043a04a20af46f10132855b79f9ff6c4f8a8ed9');
const U16BE = (n: number) => Uint8Array.of(n >>> 8, n & 0xff);
const secretChecksum = (data: Uint8Array) => {
  let checksum = 0;
  for (let i = 0; i < data.length; i++) checksum += data[i];
  return checksum % 65536;
};
const checksumOpaqueSecret = (secret: Uint8Array) => {
  const encoded = pgp.opaquempi.encode(secret);
  return concatBytes(encoded, U16BE(secretChecksum(encoded)));
};
const rawArmor = (text: string): Uint8Array =>
  base64.decode(
    text
      .trim()
      .split('\n')
      .filter((line) => line && !line.startsWith('-----') && !line.startsWith('='))
      .filter((line) => !/^[A-Za-z-]+: /.test(line))
      .join('')
  );
const tmp = <T>(fn: (dir: string) => T): T => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mkp-gpg-'));
  fs.chmodSync(dir, 0o700);
  try {
    return fn(dir);
  } finally {
    spawnSync('gpgconf', ['--homedir', dir, '--kill', 'gpg-agent'], { stdio: 'ignore' });
    fs.rmSync(dir, { recursive: true, force: true });
  }
};
const gpgLaunchAgent = (dir: string) => {
  const res = spawnSync('gpgconf', ['--homedir', dir, '--launch', 'gpg-agent'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.error) throw res.error;
  if (res.status !== 0) throw new Error(gpgReason(res.stderr || res.stdout));
};
const gpgArgs = (dir: string, args: string[]) => [
  '--no-options',
  '--homedir',
  dir,
  '--batch',
  '--yes',
  '--pinentry-mode',
  'loopback',
  '--no-tty',
  '--faked-system-time',
  GPG_TIME,
  '--no-autostart',
  ...args,
];
const gpg = (dir: string, args: string[]): string =>
  execFileSync('gpg', gpgArgs(dir, args), {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
const gpgResult = (dir: string, args: string[]) =>
  spawnSync('gpg', gpgArgs(dir, args), {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
const gpgReason = (text: string): string => {
  const lines = text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.replace(/\/tmp\/mkp-gpg-[^/\s]+/g, '<tmp>'));
  return (
    lines.find((line) => /gpg-agent|No agent|not found|No such file/i.test(line)) ||
    lines[lines.length - 1] ||
    'unknown GnuPG error'
  );
};
const gpgReady = (): GPGProbe => {
  const res = spawnSync('gpg', ['--version'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.error) return { ok: false, reason: res.error.message };
  if (res.status !== 0) return { ok: false, reason: gpgReason(res.stderr || res.stdout) };
  return { ok: true };
};
const gpgAgentReady = (): GPGProbe => {
  try {
    return tmp((dir) => {
      const key = path.join(dir, 'probe.asc');
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      fs.writeFileSync(key, keys.privateKey);
      gpgLaunchAgent(dir);
      const res = gpgResult(dir, ['--import', key]);
      if (res.error) return { ok: false, reason: res.error.message };
      if (res.status !== 0) return { ok: false, reason: gpgReason(res.stderr || res.stdout) };
      return { ok: true };
    });
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
};
const onePassInfo = (list: string): string[] =>
  list
    .split('\n')
    .filter((line) => /off=0|onepass_sig|version 3/.test(line))
    .map((line) => line.trim());
const armorHeader = (armor: string) =>
  armor.replace(/\n\n/, '\nVersion: micro-key-producer test\n\n');
const badCRC = (armor: string) => armor.replace(/\n=([A-Za-z0-9+/]{4})\n/, '\n=AAAA\n');
const primaryEd25519PublicKey = (packets: pgp.Packet[]): Uint8Array => {
  const packet = packets.find((p): p is Extract<pgp.Packet, { TAG: 'publicKey' }> => {
    return p.TAG === 'publicKey';
  });
  if (!packet) throw new Error('missing public-key packet');
  const algo = packet.data.algo;
  if (algo.TAG !== 'EdDSA' || algo.data.curve !== 'ed25519')
    throw new Error(`expected GnuPG Ed25519 public key, got ${algo.TAG}`);
  const prefixed = numberToBytesBE(algo.data.pub, 33);
  if (prefixed[0] !== 0x40) throw new Error('expected prefixed Ed25519 public point');
  return prefixed.subarray(1);
};
const fingerprintFromColons = (list: string): string => {
  const line = list.split('\n').find((l) => l.startsWith('fpr:'));
  const fingerprint = line?.split(':')[9]?.toLowerCase();
  if (!fingerprint) throw new Error('missing GnuPG fingerprint');
  return fingerprint;
};
const GPG = gpgReady();
const RUN_AGENT = process.argv.includes('--agent');
const GPG_AGENT = RUN_AGENT
  ? GPG.ok
    ? gpgAgentReady()
    : { ok: false as const, reason: GPG.reason }
  : { ok: false as const, reason: 'pass --agent to run private-key/passphrase GnuPG checks' };
const shouldAgent = (message: string, test: () => void) => {
  if (GPG_AGENT.ok) should(message, test);
  else should.skip(`${message} (requires gpg-agent: ${GPG_AGENT.reason})`, () => {});
};

if (!GPG.ok) should.skip(`pgp gpg requires GnuPG: ${GPG.reason}`, () => {});
else
  describe('pgp gpg', () => {
    shouldAgent('decodes GnuPG-generated one-pass signature packet', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      const signed = tmp((dir) => {
        const key = path.join(dir, 'key.asc');
        const msg = path.join(dir, 'msg.txt');
        const out = path.join(dir, 'msg.asc');
        fs.writeFileSync(key, keys.privateKey);
        fs.writeFileSync(msg, 'hello');
        gpgLaunchAgent(dir);
        gpg(dir, ['--import', key]);
        gpg(dir, [
          '--local-user',
          keys.keyId,
          '--armor',
          '--compress-algo',
          'none',
          '--digest-algo',
          'SHA256',
          '--sign',
          '--output',
          out,
          msg,
        ]);
        const raw = rawArmor(fs.readFileSync(out, 'utf8'));
        return {
          list: onePassInfo(gpg(dir, ['--list-packets', out])),
          onePass: raw.subarray(0, 15),
        };
      });
      deepStrictEqual(signed.list, [
        '# off=0 ctb=90 tag=4 hlen=2 plen=13',
        ':onepass_sig packet: keyid 1A9B09743C2E0B5E',
        'version 3, sigclass 0x00, digest 8, pubkey 22, last=1',
      ]);
      deepStrictEqual(hex.encode(signed.onePass), '900d030008161a9b09743c2e0b5e01');
      deepStrictEqual(pgp.Stream.decode(signed.onePass), [
        {
          TAG: 'onePassSignature',
          data: {
            version: undefined,
            type: 'binary',
            hash: 'sha256',
            algo: 'EdDSA',
            keyId: keys.keyId,
            last: true,
          },
        },
      ]);
    });
    shouldAgent('decodes GnuPG-generated OpenPGP-format packet header', () => {
      const generated = tmp((dir) => {
        const msg = path.join(dir, 'msg.txt');
        const out = path.join(dir, 'msg.gpg');
        fs.writeFileSync(msg, 'hello');
        gpgLaunchAgent(dir);
        gpg(dir, [
          '--passphrase',
          'password',
          '--symmetric',
          '--cipher-algo',
          'AES128',
          '--compress-algo',
          'none',
          '--output',
          out,
          msg,
        ]);
        const list = gpgResult(dir, ['--passphrase', 'password', '--list-packets', out])
          .stdout.split('\n')
          .filter((line) => /tag=18|encrypted data packet/.test(line))
          .map((line) => line.trim());
        return { header: fs.readFileSync(out).subarray(15, 16), list };
      });
      deepStrictEqual(generated.list, [
        '# off=15 ctb=d2 tag=18 hlen=2 plen=61 new-ctb',
        ':encrypted data packet:',
      ]);
      deepStrictEqual(hex.encode(generated.header), 'd2');
      deepStrictEqual(pgp.__TESTS.PacketHead.decode(generated.header), {
        magic: undefined,
        version: undefined,
        newFormat: true,
        tag: 'encryptedProtectedData',
      });
    });
    should('GnuPG verifies locally generated detached signatures', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      tmp((dir) => {
        const pub = path.join(dir, 'pub.asc');
        const msg = path.join(dir, 'msg.bin');
        const sig = path.join(dir, 'msg.sig.asc');
        const data = utf8.decode('hello');
        fs.writeFileSync(pub, keys.publicKey);
        fs.writeFileSync(msg, data);
        fs.writeFileSync(sig, pgp.signDetached(seed, data, keys.fingerprint, 0));
        const imported = gpgResult(dir, ['--import', pub]);
        const verified = gpgResult(dir, ['--verify', sig, msg]);
        deepStrictEqual(
          {
            imported: imported.status,
            verified: verified.status,
          },
          {
            imported: 0,
            verified: 0,
          }
        );
      });
    });
    should('GnuPG verifies locally generated canonical text detached signatures', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      tmp((dir) => {
        const pub = path.join(dir, 'pub.asc');
        const lf = path.join(dir, 'lf.txt');
        const crlf = path.join(dir, 'crlf.txt');
        const sig = path.join(dir, 'msg.sig.asc');
        const text = 'hello\nworld\n';
        fs.writeFileSync(pub, keys.publicKey);
        fs.writeFileSync(lf, utf8.decode(text));
        fs.writeFileSync(crlf, utf8.decode('hello\r\nworld\r\n'));
        fs.writeFileSync(sig, pgp.signDetached(seed, text, keys.fingerprint, 0));
        const imported = gpgResult(dir, ['--import', pub]);
        const verifiedLf = gpgResult(dir, ['--verify', sig, lf]);
        const verifiedCrlf = gpgResult(dir, ['--verify', sig, crlf]);
        deepStrictEqual(
          {
            imported: imported.status,
            verifiedLf: verifiedLf.status,
            verifiedCrlf: verifiedCrlf.status,
          },
          {
            imported: 0,
            verifiedLf: 0,
            verifiedCrlf: 0,
          }
        );
      });
    });
    shouldAgent('local verifier accepts GnuPG-generated detached signatures', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      const verified = tmp((dir) => {
        const key = path.join(dir, 'key.asc');
        const msg = path.join(dir, 'msg.bin');
        const sig = path.join(dir, 'msg.sig.asc');
        const data = utf8.decode('hello from gpg');
        fs.writeFileSync(key, keys.privateKey);
        fs.writeFileSync(msg, data);
        gpgLaunchAgent(dir);
        const imported = gpgResult(dir, ['--import', key]);
        const signed = gpgResult(dir, [
          '--local-user',
          keys.keyId,
          '--armor',
          '--digest-algo',
          'SHA512',
          '--detach-sign',
          '--output',
          sig,
          msg,
        ]);
        return {
          imported: imported.status,
          signed: signed.status,
          local: pgp.verifyDetached(
            ed25519.getPublicKey(seed),
            fs.readFileSync(sig, 'utf8'),
            data,
            keys.fingerprint
          ),
        };
      });
      deepStrictEqual(verified, {
        imported: 0,
        signed: 0,
        local: true,
      });
    });
    shouldAgent('local verifier accepts GnuPG-generated canonical text detached signatures', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      const verified = tmp((dir) => {
        const key = path.join(dir, 'key.asc');
        const msg = path.join(dir, 'msg.txt');
        const sig = path.join(dir, 'msg.sig.asc');
        const lf = 'hello\nfrom gpg\n';
        fs.writeFileSync(key, keys.privateKey);
        fs.writeFileSync(msg, utf8.decode(lf));
        gpgLaunchAgent(dir);
        const imported = gpgResult(dir, ['--import', key]);
        const signed = gpgResult(dir, [
          '--local-user',
          keys.keyId,
          '--armor',
          '--textmode',
          '--digest-algo',
          'SHA512',
          '--detach-sign',
          '--output',
          sig,
          msg,
        ]);
        return {
          imported: imported.status,
          signed: signed.status,
          localLf: pgp.verifyDetached(
            ed25519.getPublicKey(seed),
            fs.readFileSync(sig, 'utf8'),
            lf,
            keys.fingerprint
          ),
          localCrlf: pgp.verifyDetached(
            ed25519.getPublicKey(seed),
            fs.readFileSync(sig, 'utf8'),
            'hello\r\nfrom gpg\r\n',
            keys.fingerprint
          ),
        };
      });
      deepStrictEqual(verified, {
        imported: 0,
        signed: 0,
        localLf: true,
        localCrlf: true,
      });
    });
    shouldAgent('local verifier accepts GnuPG-generated expiring detached signatures', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      const verified = tmp((dir) => {
        const key = path.join(dir, 'key.asc');
        const msg = path.join(dir, 'msg.bin');
        const sig = path.join(dir, 'msg.sig.asc');
        const data = utf8.decode('hello expiring signature');
        fs.writeFileSync(key, keys.privateKey);
        fs.writeFileSync(msg, data);
        gpgLaunchAgent(dir);
        const imported = gpgResult(dir, ['--import', key]);
        const signed = gpgResult(dir, [
          '--local-user',
          keys.keyId,
          '--armor',
          '--digest-algo',
          'SHA512',
          '--default-sig-expire',
          '1d',
          '--detach-sign',
          '--output',
          sig,
          msg,
        ]);
        const packet = pgp.sigArmor.decode(fs.readFileSync(sig, 'utf8'))[0];
        if (!packet || packet.TAG !== 'signature') throw new Error('missing signature packet');
        return {
          imported: imported.status,
          signed: signed.status,
          expiration: packet.data.head.hashed.find((s) => s.TAG === 'signatureExpirationTime'),
          local: pgp.verifyDetached(
            ed25519.getPublicKey(seed),
            fs.readFileSync(sig, 'utf8'),
            data,
            keys.fingerprint
          ),
        };
      });
      deepStrictEqual(verified, {
        imported: 0,
        signed: 0,
        expiration: { TAG: 'signatureExpirationTime', data: 86400, critical: true },
        local: true,
      });
    });
    shouldAgent('local verifier accepts GnuPG-generated notation and URI subpackets', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      const verified = tmp((dir) => {
        const key = path.join(dir, 'key.asc');
        const msg = path.join(dir, 'msg.bin');
        const data = utf8.decode('hello annotated signature');
        fs.writeFileSync(key, keys.privateKey);
        fs.writeFileSync(msg, data);
        gpgLaunchAgent(dir);
        const imported = gpgResult(dir, ['--import', key]);
        const cases = [
          {
            name: 'notation',
            args: ['--sig-notation', 'test@example.com=value'],
            tag: 'notationData',
          },
          {
            name: 'policy',
            args: ['--sig-policy-url', 'https://example.com/policy'],
            tag: 'policyURI',
          },
          {
            name: 'keyserver',
            args: ['--sig-keyserver-url', 'https://keys.example.com'],
            tag: 'preferredKeyServer',
          },
        ];
        return {
          imported: imported.status,
          results: cases.map((c) => {
            const sig = path.join(dir, `${c.name}.sig.asc`);
            const signed = gpgResult(dir, [
              '--local-user',
              keys.keyId,
              '--armor',
              '--digest-algo',
              'SHA512',
              ...c.args,
              '--detach-sign',
              '--output',
              sig,
              msg,
            ]);
            const text = fs.readFileSync(sig, 'utf8');
            const packet = pgp.sigArmor.decode(text)[0];
            if (!packet || packet.TAG !== 'signature') throw new Error('missing signature packet');
            return {
              name: c.name,
              signed: signed.status,
              subpacket: packet.data.head.hashed.find((s) => s.TAG === c.tag),
              local: pgp.verifyDetached(ed25519.getPublicKey(seed), text, data, keys.fingerprint),
            };
          }),
        };
      });
      deepStrictEqual(verified, {
        imported: 0,
        results: [
          {
            name: 'notation',
            signed: 0,
            subpacket: {
              TAG: 'notationData',
              data: { humanReadable: true, name: 'test@example.com', value: utf8.decode('value') },
            },
            local: true,
          },
          {
            name: 'policy',
            signed: 0,
            subpacket: { TAG: 'policyURI', data: 'https://example.com/policy' },
            local: true,
          },
          {
            name: 'keyserver',
            signed: 0,
            subpacket: { TAG: 'preferredKeyServer', data: 'https://keys.example.com' },
            local: true,
          },
        ],
      });
    });
    shouldAgent('local verifier accepts GnuPG-generated key and detached signature', () => {
      const verified = tmp((dir) => {
        const msg = path.join(dir, 'msg.bin');
        const sig = path.join(dir, 'msg.sig.asc');
        const data = utf8.decode('hello from generated gpg key');
        gpgLaunchAgent(dir);
        const generated = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Generated <generated@example.com>',
          'ed25519',
          'sign',
          '0',
        ]);
        const publicKey = primaryEd25519PublicKey(
          pgp.pubArmor.decode(gpg(dir, ['--armor', '--export', 'generated@example.com']))
        );
        const fingerprint = fingerprintFromColons(
          gpg(dir, ['--with-colons', '--fingerprint', 'generated@example.com'])
        );
        fs.writeFileSync(msg, data);
        const signed = gpgResult(dir, [
          '--local-user',
          'generated@example.com',
          '--armor',
          '--digest-algo',
          'SHA512',
          '--detach-sign',
          '--output',
          sig,
          msg,
        ]);
        return {
          generated: generated.status,
          signed: signed.status,
          local: pgp.verifyDetached(publicKey, fs.readFileSync(sig, 'utf8'), data, fingerprint),
        };
      });
      deepStrictEqual(verified, {
        generated: 0,
        signed: 0,
        local: true,
      });
    });
    shouldAgent('local parser accepts GnuPG-generated expiring public keys', () => {
      const decoded = tmp((dir) => {
        gpgLaunchAgent(dir);
        const generated = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Expiring <expiring@example.com>',
          'ed25519',
          'sign',
          '1d',
        ]);
        const packets = pgp.pubArmor.decode(
          gpg(dir, ['--armor', '--export', 'expiring@example.com'])
        );
        const sig = packets.find((p): p is Extract<pgp.Packet, { TAG: 'signature' }> => {
          return p.TAG === 'signature';
        });
        if (!sig) throw new Error('missing self-signature');
        return {
          generated: generated.status,
          packets: packets.map((p) => p.TAG),
          keyExpirationTime: sig.data.head.hashed.find((s) => s.TAG === 'keyExpirationTime'),
        };
      });
      deepStrictEqual(decoded, {
        generated: 0,
        packets: ['publicKey', 'userId', 'signature'],
        keyExpirationTime: { TAG: 'keyExpirationTime', data: 86400 },
      });
    });
    shouldAgent('local parser accepts GnuPG-generated revocation certificates', () => {
      const decoded = tmp((dir) => {
        gpgLaunchAgent(dir);
        const generated = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Revoked <revoked@example.com>',
          'ed25519',
          'sign',
          '0',
        ]);
        const revDir = path.join(dir, 'openpgp-revocs.d');
        const revFile = fs.readdirSync(revDir)[0];
        const lines = fs
          .readFileSync(path.join(revDir, revFile), 'utf8')
          .split('\n')
          .map((line) => (line.startsWith(':') ? line.slice(1) : line));
        const begin = lines.findIndex((line) => line.startsWith('-----BEGIN'));
        const armor = lines.slice(begin).join('\n');
        const packets = pgp.pubArmor.decode(armor);
        const sig = packets.find((p): p is Extract<pgp.Packet, { TAG: 'signature' }> => {
          return p.TAG === 'signature';
        });
        if (!sig) throw new Error('missing revocation signature');
        return {
          generated: generated.status,
          packets: packets.map((p) => p.TAG),
          reason: sig.data.head.hashed.find((s) => s.TAG === 'reasonForRevocation'),
        };
      });
      deepStrictEqual(decoded, {
        generated: 0,
        packets: ['signature'],
        reason: { TAG: 'reasonForRevocation', data: { code: 0, reason: '' } },
      });
    });
    shouldAgent('local parser accepts GnuPG-generated local certifications', () => {
      const decoded = tmp((dir) => {
        gpgLaunchAgent(dir);
        const generatedAlice = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Alice <alice@example.com>',
          'ed25519',
          'sign',
          '0',
        ]);
        const generatedBob = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Bob <bob@example.com>',
          'ed25519',
          'sign',
          '0',
        ]);
        const bobFingerprint = fingerprintFromColons(
          gpg(dir, ['--with-colons', '--fingerprint', 'bob@example.com'])
        );
        const signed = gpgResult(dir, [
          '--local-user',
          'alice@example.com',
          '--quick-lsign-key',
          bobFingerprint,
        ]);
        const packets = pgp.pubArmor.decode(
          gpg(dir, [
            '--armor',
            '--export-options',
            'export-local-sigs',
            '--export',
            'bob@example.com',
          ])
        );
        const exportability = packets
          .filter((p): p is Extract<pgp.Packet, { TAG: 'signature' }> => p.TAG === 'signature')
          .map((p) => p.data.head.hashed.find((s) => s.TAG === 'exportableCertification'))
          .filter((s) => !!s);
        return {
          generatedAlice: generatedAlice.status,
          generatedBob: generatedBob.status,
          signed: signed.status,
          exportability,
        };
      });
      deepStrictEqual(decoded, {
        generatedAlice: 0,
        generatedBob: 0,
        signed: 0,
        exportability: [{ TAG: 'exportableCertification', data: false }],
      });
    });
    shouldAgent('local parser accepts GnuPG-generated designated revoker subpackets', () => {
      const decoded = tmp((dir) => {
        gpgLaunchAgent(dir);
        const generatedRevoker = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Revoker <revoker@example.com>',
          'ed25519',
          'sign',
          '0',
        ]);
        const revokerFingerprint = fingerprintFromColons(
          gpg(dir, ['--with-colons', '--fingerprint', 'revoker@example.com'])
        );
        const generatedTarget = gpgResult(dir, [
          '--passphrase',
          '',
          '--add-desig-revoker',
          revokerFingerprint,
          '--quick-gen-key',
          'Target <target@example.com>',
          'ed25519',
          'sign',
          '0',
        ]);
        const packets = pgp.pubArmor.decode(
          gpg(dir, ['--armor', '--export', 'target@example.com'])
        );
        const sig = packets.find((p): p is Extract<pgp.Packet, { TAG: 'signature' }> => {
          return p.TAG === 'signature';
        });
        if (!sig) throw new Error('missing direct-key signature');
        return {
          generatedRevoker: generatedRevoker.status,
          generatedTarget: generatedTarget.status,
          revokerFingerprint: revokerFingerprint.toLowerCase(),
          revocationKey: sig.data.head.hashed.find((s) => s.TAG === 'revocationKey'),
          revocable: sig.data.head.hashed.find((s) => s.TAG === 'revocable'),
        };
      });
      deepStrictEqual(decoded, {
        generatedRevoker: 0,
        generatedTarget: 0,
        revokerFingerprint: decoded.revokerFingerprint,
        revocationKey: {
          TAG: 'revocationKey',
          data: { class: 0x80, algo: 'EdDSA', fingerprint: decoded.revokerFingerprint },
        },
        revocable: { TAG: 'revocable', data: false },
      });
    });
    shouldAgent('local parser accepts GnuPG-generated signing subkey back-signatures', () => {
      const decoded = tmp((dir) => {
        gpgLaunchAgent(dir);
        const generated = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-gen-key',
          'Subkey <subkey@example.com>',
          'ed25519',
          'cert',
          '0',
        ]);
        const fingerprint = fingerprintFromColons(
          gpg(dir, ['--with-colons', '--fingerprint', 'subkey@example.com'])
        );
        const added = gpgResult(dir, [
          '--passphrase',
          '',
          '--quick-add-key',
          fingerprint,
          'ed25519',
          'sign',
          '0',
        ]);
        const armor = gpg(dir, ['--armor', '--export', 'subkey@example.com']);
        const packets = pgp.pubArmor.decode(armor);
        const subkeySig = packets
          .filter((p): p is Extract<pgp.Packet, { TAG: 'signature' }> => p.TAG === 'signature')
          .find((p) => p.data.head.hashed.some((s) => s.TAG === 'keyFlags' && !!s.data.sign));
        if (!subkeySig) throw new Error('missing signing-subkey binding signature');
        return {
          generated: generated.status,
          added: added.status,
          packets: packets.map((p) => p.TAG),
          embedded: subkeySig.data.unhashed.find((s) => s.TAG === 'embeddedSignature')?.TAG,
          roundtrip: hex.encode(pgp.Stream.encode(packets)) === hex.encode(rawArmor(armor)),
        };
      });
      deepStrictEqual(decoded, {
        generated: 0,
        added: 0,
        packets: ['publicKey', 'userId', 'signature', 'publicSubkey', 'signature'],
        embedded: 'embeddedSignature',
        roundtrip: true,
      });
    });
    shouldAgent('GnuPG accepts legacy direct-cipher secret-key packets', () => {
      const password = 'password';
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', password, 0);
      const direct = (() => {
        const packets = pgp.privArmor.decode(keys.privateKey);
        const secretKey = secretKeyPacket(packets);
        const iv = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
        const secret = cfb(md5(utf8.decode(password)), iv).encrypt(checksumOpaqueSecret(seed));
        return packets.map((p) =>
          p.TAG === 'secretKey'
            ? {
                ...p,
                data: {
                  pub: secretKey.pub,
                  type: { TAG: 'encryptedDirect', data: { enc: 'aes128', iv, secret } },
                },
              }
            : p
        );
      })();
      deepStrictEqual(
        direct
          .filter((p) => p.TAG === 'secretKey' || p.TAG === 'secretSubkey')
          .map((p) => p.data.type.TAG),
        ['encryptedDirect', 'encrypted']
      );
      tmp((dir) => {
        const key = path.join(dir, 'key.asc');
        const msg = path.join(dir, 'msg.txt');
        const sig = path.join(dir, 'msg.sig.asc');
        fs.writeFileSync(key, pgp.privArmor.encode(direct));
        fs.writeFileSync(msg, 'hello');
        gpgLaunchAgent(dir);
        const imported = gpgResult(dir, ['--import', key]);
        const signed = gpgResult(dir, [
          '--passphrase',
          password,
          '--local-user',
          keys.keyId,
          '--armor',
          '--detach-sign',
          '--output',
          sig,
          msg,
        ]);
        const verified = gpgResult(dir, ['--verify', sig, msg]);
        deepStrictEqual(
          {
            imported: imported.status,
            signed: signed.status,
            verified: verified.status,
            localSecret: pgp.decodeSecretKey(password, secretKeyPacket(direct)),
          },
          {
            imported: 0,
            signed: 0,
            verified: 0,
            localSecret: BigInt(`0x${hex.encode(seed)}`),
          }
        );
      });
    });
    should('GnuPG and local armor handling agree on headers and strict CRC24', () => {
      const keys = pgp.getKeys(seed, 'gpg <gpg@example.com>', undefined, 0);
      const msgBytes = utf8.decode('hello');
      const signature = pgp.signDetached(seed, msgBytes, keys.fingerprint, 0);
      const pubHeader = armorHeader(keys.publicKey);
      const privHeader = armorHeader(keys.privateKey);
      const sigHeader = armorHeader(signature);
      const pubBad = badCRC(keys.publicKey);
      const privBad = badCRC(keys.privateKey);
      const sigBad = badCRC(signature);
      deepStrictEqual(pgp.pubArmor.decode(pubHeader), pgp.pubArmor.decode(keys.publicKey));
      deepStrictEqual(pgp.privArmor.decode(privHeader), pgp.privArmor.decode(keys.privateKey));
      deepStrictEqual(pgp.sigArmor.decode(sigHeader), pgp.sigArmor.decode(signature));
      throws(() => pgp.pubArmor.decode(pubBad), /invalid checksum/);
      throws(() => pgp.privArmor.decode(privBad), /invalid checksum/);
      throws(() => pgp.sigArmor.decode(sigBad), /invalid checksum/);
      const statuses = tmp((dir) => {
        const msg = path.join(dir, 'msg.bin');
        const goodPub = path.join(dir, 'pub-header.asc');
        const goodPriv = path.join(dir, 'priv-header.asc');
        const goodSig = path.join(dir, 'sig-header.asc');
        const badPub = path.join(dir, 'pub-bad-crc.asc');
        const badPriv = path.join(dir, 'priv-bad-crc.asc');
        const badSig = path.join(dir, 'sig-bad-crc.asc');
        fs.writeFileSync(msg, msgBytes);
        fs.writeFileSync(goodPub, pubHeader);
        fs.writeFileSync(goodPriv, privHeader);
        fs.writeFileSync(goodSig, sigHeader);
        fs.writeFileSync(badPub, pubBad);
        fs.writeFileSync(badPriv, privBad);
        fs.writeFileSync(badSig, sigBad);
        const badPublicImport = gpgResult(dir, ['--import', badPub]);
        if (GPG_AGENT.ok) gpgLaunchAgent(dir);
        const badPrivateImport = GPG_AGENT.ok
          ? gpgResult(dir, ['--import', badPriv])
          : { status: undefined };
        const publicImport = gpgResult(dir, ['--import', goodPub]);
        const privateImport = GPG_AGENT.ok
          ? gpgResult(dir, ['--import', goodPriv])
          : { status: undefined };
        const goodSignatureVerify = gpgResult(dir, ['--verify', goodSig, msg]);
        const badSignatureVerify = gpgResult(dir, ['--verify', badSig, msg]);
        return {
          badPublicImport: badPublicImport.status,
          badPrivateImport: badPrivateImport.status,
          publicImport: publicImport.status,
          privateImport: privateImport.status,
          goodSignatureVerify: goodSignatureVerify.status,
          badSignatureVerify: badSignatureVerify.status,
        };
      });
      deepStrictEqual(statuses, {
        badPublicImport: 2,
        badPrivateImport: GPG_AGENT.ok ? 2 : undefined,
        publicImport: 0,
        privateImport: GPG_AGENT.ok ? 0 : undefined,
        goodSignatureVerify: 0,
        badSignatureVerify: 2,
      });
    });
  });

should.runWhen(import.meta.url);
