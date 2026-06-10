import { equalBytes } from '@noble/curves/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { base64 } from '@scure/base';
import { deepStrictEqual } from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CMS, X509 } from '../src/x509.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, 'vectors', 'certs');
const PKITS = 'pkits';
const PATH_DISCOVERY = path.join('path-discovery', 'Path Discovery Test Suite');
const PKITS_TIME = Date.UTC(2020, 0, 1);

type Result = 'pass' | 'fail';
type PkitsCase = {
  section: string;
  title: string;
  smime: string;
  expected: Result;
};

const read = (name: string): Uint8Array => new Uint8Array(fs.readFileSync(path.join(ROOT, name)));
const readText = (name: string): string => fs.readFileSync(path.join(ROOT, name), 'utf8');
const count = (map: Record<string, number>, key: string): void => {
  map[key] = (map[key] || 0) + 1;
};
const push = (map: Record<string, string[]>, key: string, value: string): void => {
  const list = map[key] || [];
  list.push(value);
  map[key] = list;
};
const sorted = (map: Record<string, number>): Record<string, number> =>
  Object.fromEntries(Object.entries(map).sort(([a], [b]) => a.localeCompare(b)));
const sortedLists = (map: Record<string, string[]>): Record<string, string[]> =>
  Object.fromEntries(
    Object.entries(map)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, v.sort()])
  );
const files = (dir: string, ext?: string): string[] => {
  const base = path.join(ROOT, dir);
  const out: string[] = [];
  for (const name of fs.readdirSync(base).sort()) {
    const full = path.join(base, name);
    const rel = path.join(dir, name);
    if (fs.statSync(full).isDirectory()) {
      out.push(...files(rel, ext));
      continue;
    }
    if (!ext || name.toLowerCase().endsWith(ext)) out.push(rel);
  }
  return out;
};
const cmsFromEml = (name: string): Uint8Array => {
  const lines = readText(name).split(/\r?\n/);
  let best = '';
  for (let i = 0; i < lines.length; i++) {
    if (!/^Content-Transfer-Encoding:\s*base64/i.test(lines[i])) continue;
    let j = i + 1;
    while (j < lines.length && lines[j].trim() !== '') j++;
    j++;
    const body: string[] = [];
    for (; j < lines.length; j++) {
      const line = lines[j].trim();
      if (!line) continue;
      if (line.startsWith('--')) break;
      if (!/^[A-Za-z0-9+/=]+$/.test(line)) break;
      body.push(line);
    }
    const b64 = body.join('');
    if (b64.length > best.length) best = b64;
  }
  if (!best) throw new Error(`base64 CMS part not found in ${name}`);
  try {
    return base64.decode(best);
  } catch {
    // Bun and Node report different native base64 decoder text; keep fixture
    // bucket assertions about the malformed S/MIME part, not engine wording.
    throw new Error('invalid base64 CMS part');
  }
};
const reachesTrust = (
  chain: ReturnType<typeof CMS.verify>['chain'],
  trust: Uint8Array
): boolean => {
  const last = chain[chain.length - 1];
  if (!last) return false;
  return equalBytes(X509.encode(last), trust);
};
const certFixtureNames = (): string[] => [
  ...files(path.join(PKITS, 'certs'), '.crt'),
  ...files(path.join(PATH_DISCOVERY, 'End Entity Certs'), '.crt'),
  ...files(path.join(PATH_DISCOVERY, 'Trust Anchor Certs'), '.crt'),
];
const nistResult = (test: PkitsCase, trust: Uint8Array) => {
  try {
    const der = cmsFromEml(path.join(PKITS, 'smime', test.smime));
    const verified = CMS.verify(der, {
      time: PKITS_TIME,
      chain: [trust],
      checkSignatures: false,
    });
    const actual = reachesTrust(verified.chain, trust) ? 'pass' : 'fail';
    return {
      section: test.section,
      title: test.title,
      expected: test.expected,
      actual,
      chain: verified.chain.length,
      error: undefined,
    };
  } catch (e) {
    return {
      section: test.section,
      title: test.title,
      expected: test.expected,
      actual: 'fail' as const,
      chain: 0,
      error: e instanceof Error ? e.message : String(e),
    };
  }
};

const PKITS_CASES: PkitsCase[] = [
  {
    section: '4.2.1',
    title: 'Invalid CA notBefore Date Test1',
    smime: 'SignedInvalidCAnotBeforeDateTest1.eml',
    expected: 'fail',
  },
  {
    section: '4.2.2',
    title: 'Invalid EE notBefore Date Test2',
    smime: 'SignedInvalidEEnotBeforeDateTest2.eml',
    expected: 'fail',
  },
  {
    section: '4.2.3',
    title: 'Valid pre2000 UTC notBefore Date Test3',
    smime: 'SignedValidpre2000UTCnotBeforeDateTest3.eml',
    expected: 'pass',
  },
  {
    section: '4.2.4',
    title: 'Valid GeneralizedTime notBefore Date Test4',
    smime: 'SignedValidGeneralizedTimenotBeforeDateTest4.eml',
    expected: 'pass',
  },
  {
    section: '4.2.5',
    title: 'Invalid CA notAfter Date Test5',
    smime: 'SignedInvalidCAnotAfterDateTest5.eml',
    expected: 'fail',
  },
  {
    section: '4.2.6',
    title: 'Invalid EE notAfter Date Test6',
    smime: 'SignedInvalidEEnotAfterDateTest6.eml',
    expected: 'fail',
  },
  {
    section: '4.2.7',
    title: 'Invalid pre2000 UTC EE notAfter Date Test7',
    smime: 'SignedInvalidpre2000UTCEEnotAfterDateTest7.eml',
    expected: 'fail',
  },
  {
    section: '4.2.8',
    title: 'Valid GeneralizedTime notAfter Date Test8',
    smime: 'SignedValidGeneralizedTimenotAfterDateTest8.eml',
    expected: 'pass',
  },
  {
    section: '4.3.1',
    title: 'Invalid Name Chaining EE Test1',
    smime: 'SignedInvalidNameChainingEETest1.eml',
    expected: 'fail',
  },
  {
    section: '4.3.2',
    title: 'Invalid Name Chaining Order Test2',
    smime: 'SignedInvalidNameChainingOrderTest2.eml',
    expected: 'fail',
  },
  {
    section: '4.3.3',
    title: 'Valid Name Chaining Whitespace Test3',
    smime: 'SignedValidNameChainingWhitespaceTest3.eml',
    expected: 'pass',
  },
  {
    section: '4.3.4',
    title: 'Valid Name Chaining Whitespace Test4',
    smime: 'SignedValidNameChainingWhitespaceTest4.eml',
    expected: 'pass',
  },
  {
    section: '4.3.5',
    title: 'Valid Name Chaining Capitalization Test5',
    smime: 'SignedValidNameChainingCapitalizationTest5.eml',
    expected: 'pass',
  },
  {
    section: '4.3.6',
    title: 'Valid Name Chaining UIDs Test6',
    smime: 'SignedValidNameChainingUIDsTest6.eml',
    expected: 'pass',
  },
  {
    section: '4.3.7',
    title: 'Valid RFC3280 Mandatory Attribute Types Test7',
    smime: 'SignedValidRFC3280MandatoryAttributeTypesTest7.eml',
    expected: 'pass',
  },
  {
    section: '4.3.8',
    title: 'Valid RFC3280 Optional Attribute Types Test8',
    smime: 'SignedValidRFC3280OptionalAttributeTypesTest8.eml',
    expected: 'pass',
  },
  {
    section: '4.3.9',
    title: 'Valid UTF8String Encoded Names Test9',
    smime: 'SignedValidUTF8StringEncodedNamesTest9.eml',
    expected: 'pass',
  },
  {
    section: '4.3.10',
    title: 'Valid Rollover from PrintableString to UTF8String Test10',
    smime: 'SignedValidRolloverfromPrintableStringtoUTF8StringTest10.eml',
    expected: 'pass',
  },
  {
    section: '4.3.11',
    title: 'Valid UTF8String Case Insensitive Match Test11',
    smime: 'SignedValidUTF8StringCaseInsensitiveMatchTest11.eml',
    expected: 'pass',
  },
  {
    section: '4.5.1',
    title: 'Valid Basic Self-Issued Old With New Test1',
    smime: 'SignedValidBasicSelfIssuedOldWithNewTest1.eml',
    expected: 'pass',
  },
  {
    section: '4.5.2',
    title: 'Invalid Basic Self-Issued Old With New Test2',
    smime: 'SignedInvalidBasicSelfIssuedOldWithNewTest2.eml',
    expected: 'fail',
  },
  {
    section: '4.5.3',
    title: 'Valid Basic Self-Issued New With Old Test3',
    smime: 'SignedValidBasicSelfIssuedNewWithOldTest3.eml',
    expected: 'pass',
  },
  {
    section: '4.5.4',
    title: 'Valid Basic Self-Issued New With Old Test4',
    smime: 'SignedValidBasicSelfIssuedNewWithOldTest4.eml',
    expected: 'pass',
  },
  {
    section: '4.5.5',
    title: 'Invalid Basic Self-Issued New With Old Test5',
    smime: 'SignedInvalidBasicSelfIssuedNewWithOldTest5.eml',
    expected: 'fail',
  },
  {
    section: '4.5.6',
    title: 'Valid Basic Self-Issued CRL Signing Key Test6',
    smime: 'SignedValidBasicSelfIssuedCRLSigningKeyTest6.eml',
    expected: 'pass',
  },
  {
    section: '4.5.7',
    title: 'Invalid Basic Self-Issued CRL Signing Key Test7',
    smime: 'SignedInvalidBasicSelfIssuedCRLSigningKeyTest7.eml',
    expected: 'fail',
  },
  {
    section: '4.5.8',
    title: 'Invalid Basic Self-Issued CRL Signing Key Test8',
    smime: 'SignedInvalidBasicSelfIssuedCRLSigningKeyTest8.eml',
    expected: 'fail',
  },
  {
    section: '4.6.1',
    title: 'Invalid Missing basicConstraints Test1',
    smime: 'SignedInvalidMissingbasicConstraintsTest1.eml',
    expected: 'fail',
  },
  {
    section: '4.6.2',
    title: 'Invalid cA False Test2',
    smime: 'SignedInvalidcAFalseTest2.eml',
    expected: 'fail',
  },
  {
    section: '4.6.3',
    title: 'Invalid cA False Test3',
    smime: 'SignedInvalidcAFalseTest3.eml',
    expected: 'fail',
  },
  {
    section: '4.6.4',
    title: 'Valid basicConstraints Not Critical Test4',
    smime: 'SignedValidbasicConstraintsNotCriticalTest4.eml',
    expected: 'pass',
  },
  {
    section: '4.6.5',
    title: 'Invalid pathLenConstraint Test5',
    smime: 'SignedInvalidpathLenConstraintTest5.eml',
    expected: 'fail',
  },
  {
    section: '4.6.6',
    title: 'Invalid pathLenConstraint Test6',
    smime: 'SignedInvalidpathLenConstraintTest6.eml',
    expected: 'fail',
  },
  {
    section: '4.6.7',
    title: 'Valid pathLenConstraint Test7',
    smime: 'SignedValidpathLenConstraintTest7.eml',
    expected: 'pass',
  },
  {
    section: '4.6.8',
    title: 'Valid pathLenConstraint Test8',
    smime: 'SignedValidpathLenConstraintTest8.eml',
    expected: 'pass',
  },
  {
    section: '4.6.9',
    title: 'Invalid pathLenConstraint Test9',
    smime: 'SignedInvalidpathLenConstraintTest9.eml',
    expected: 'fail',
  },
  {
    section: '4.6.10',
    title: 'Invalid pathLenConstraint Test10',
    smime: 'SignedInvalidpathLenConstraintTest10.eml',
    expected: 'fail',
  },
  {
    section: '4.6.11',
    title: 'Invalid pathLenConstraint Test11',
    smime: 'SignedInvalidpathLenConstraintTest11.eml',
    expected: 'fail',
  },
  {
    section: '4.6.12',
    title: 'Invalid pathLenConstraint Test12',
    smime: 'SignedInvalidpathLenConstraintTest12.eml',
    expected: 'fail',
  },
  {
    section: '4.6.13',
    title: 'Valid pathLenConstraint Test13',
    smime: 'SignedValidpathLenConstraintTest13.eml',
    expected: 'pass',
  },
  {
    section: '4.6.14',
    title: 'Valid pathLenConstraint Test14',
    smime: 'SignedValidpathLenConstraintTest14.eml',
    expected: 'pass',
  },
  {
    section: '4.6.15',
    title: 'Valid Self-Issued pathLenConstraint Test15',
    smime: 'SignedValidSelfIssuedpathLenConstraintTest15.eml',
    expected: 'pass',
  },
  {
    section: '4.6.16',
    title: 'Invalid Self-Issued pathLenConstraint Test16',
    smime: 'SignedInvalidSelfIssuedpathLenConstraintTest16.eml',
    expected: 'fail',
  },
  {
    section: '4.6.17',
    title: 'Valid Self-Issued pathLenConstraint Test17',
    smime: 'SignedValidSelfIssuedpathLenConstraintTest17.eml',
    expected: 'pass',
  },
  {
    section: '4.7.1',
    title: 'Invalid keyUsage Critical keyCertSign False Test1',
    smime: 'SignedInvalidkeyUsageCriticalkeyCertSignFalseTest1.eml',
    expected: 'fail',
  },
  {
    section: '4.7.2',
    title: 'Invalid keyUsage Not Critical keyCertSign False Test2',
    smime: 'SignedInvalidkeyUsageNotCriticalkeyCertSignFalseTest2.eml',
    expected: 'fail',
  },
  {
    section: '4.7.3',
    title: 'Valid keyUsage Not Critical Test3',
    smime: 'SignedValidkeyUsageNotCriticalTest3.eml',
    expected: 'pass',
  },
  {
    section: '4.7.4',
    title: 'Invalid keyUsage Critical cRLSign False Test4',
    smime: 'SignedInvalidkeyUsageCriticalcRLSignFalseTest4.eml',
    expected: 'fail',
  },
  {
    section: '4.7.5',
    title: 'Invalid keyUsage Not Critical cRLSign False Test5',
    smime: 'SignedInvalidkeyUsageNotCriticalcRLSignFalseTest5.eml',
    expected: 'fail',
  },
  {
    section: '4.16.1',
    title: 'Valid Unknown Not Critical Certificate Extension Test1',
    smime: 'SignedValidUnknownNotCriticalCertificateExtensionTest1.eml',
    expected: 'pass',
  },
  {
    section: '4.16.2',
    title: 'Invalid Unknown Critical Certificate Extension Test2',
    smime: 'SignedInvalidUnknownCriticalCertificateExtensionTest2.eml',
    expected: 'fail',
  },
];
const PKITS_UNSUPPORTED_REVOCATION: Record<string, string> = {
  '4.5.2':
    'PKITS.pdf section 4.5.2 fails only because the end-entity certificate has been revoked.',
  '4.5.5':
    'PKITS.pdf section 4.5.5 fails only because the end-entity certificate has been revoked.',
  '4.5.7':
    'PKITS.pdf section 4.5.7 fails only because the end-entity certificate has been revoked.',
  '4.7.4': 'PKITS.pdf section 4.7.4 fails only because CRL validation needs cRLSign.',
  '4.7.5': 'PKITS.pdf section 4.7.5 fails only because CRL validation needs cRLSign.',
};

describe('x509 nist', () => {
  should('imported fixture counts match the extracted NIST PDF manifest', () => {
    // PKITS.pdf section 4 has 224 validation tests; section 6.2.2 has 224 S/MIME messages.
    // PathDiscoveryTestSuite.pdf section 4 has 39 path discovery tests; section 5.3.2 maps to 75 messages.
    deepStrictEqual(
      {
        pkits: {
          manifestTests: 224,
          manifestSmime: 224,
          certs: files(path.join(PKITS, 'certs')).length,
          crls: files(path.join(PKITS, 'crls')).length,
          certpairs: files(path.join(PKITS, 'certpairs')).length,
          smime: files(path.join(PKITS, 'smime'), '.eml').length,
        },
        pathDiscovery: {
          manifestTests: 39,
          manifestSmime: 75,
          endEntityCerts: files(path.join(PATH_DISCOVERY, 'End Entity Certs')).length,
          trustAnchors: files(path.join(PATH_DISCOVERY, 'Trust Anchor Certs')).length,
          smime: files(path.join(PATH_DISCOVERY, 'smime'), '.eml').length,
        },
      },
      {
        pkits: {
          manifestTests: 224,
          manifestSmime: 224,
          certs: 405,
          crls: 173,
          certpairs: 348,
          smime: 224,
        },
        pathDiscovery: {
          manifestTests: 39,
          manifestSmime: 75,
          endEntityCerts: 75,
          trustAnchors: 3,
          smime: 75,
        },
      }
    );
  });
  should('DER certificate fixtures decode and roundtrip in current support buckets', () => {
    const decoded: Record<string, number> = {};
    const errors: Record<string, number> = {};
    const mismatch: string[] = [];
    const names = certFixtureNames();
    for (const name of names) {
      try {
        const der = read(name);
        const cert = X509.decode(der);
        count(decoded, cert.tbs.spki.algorithm.algorithm);
        if (!equalBytes(X509.encode(cert), der)) mismatch.push(name);
      } catch (e) {
        count(errors, e instanceof Error ? e.message : String(e));
      }
    }
    deepStrictEqual(
      { total: names.length, decoded: sorted(decoded), errors: sorted(errors), mismatch },
      {
        total: 483,
        decoded: {
          DSA: 4,
          rsaEncryption: 476,
        },
        errors: {
          'Reader(): Error: Reader(sig): Error: Reader(): Error: ASN1.bitString: non-zero amount of leftover bits': 2,
          'Reader(): Error: Reader(tbs): Error: Reader(serial): Error: Reader(): Error: negative values not allowed': 1,
        },
        mismatch: [],
      }
    );
  });
  should('S/MIME fixtures decode and roundtrip in current support buckets', () => {
    const check = (names: string[]) => {
      const errors: Record<string, string[]> = {};
      const mismatch: string[] = [];
      let contentInfo = 0;
      let signedData = 0;
      for (const name of names) {
        let der: Uint8Array;
        try {
          der = cmsFromEml(name);
        } catch (e) {
          push(errors, `eml: ${e instanceof Error ? e.message : String(e)}`, name);
          continue;
        }
        try {
          const decoded = CMS.decode(der);
          contentInfo++;
          if (!equalBytes(CMS.encode(decoded), der)) mismatch.push(name);
        } catch (e) {
          push(errors, `CMS.decode: ${e instanceof Error ? e.message : String(e)}`, name);
          continue;
        }
        try {
          CMS.signed(der);
          signedData++;
        } catch (e) {
          push(errors, `CMS.signed: ${e instanceof Error ? e.message : String(e)}`, name);
        }
      }
      return {
        total: names.length,
        contentInfo,
        signedData,
        mismatch,
        errors: sortedLists(errors),
      };
    };
    deepStrictEqual(
      {
        pkits: check(files(path.join(PKITS, 'smime'), '.eml')),
        pathDiscovery: check(files(path.join(PATH_DISCOVERY, 'smime'), '.eml')),
      },
      {
        pkits: {
          total: 224,
          contentInfo: 224,
          signedData: 220,
          mismatch: [],
          errors: {
            'CMS.signed: Reader(): Error: Reader(certificates): Error: Reader(0): Error: Reader(): Error: Reader(): Error: Reader(sig): Error: Reader(): Error: ASN1.bitString: non-zero amount of leftover bits':
              ['pkits/smime/SignedInvalidCASignatureTest2.eml'],
            'CMS.signed: Reader(): Error: Reader(certificates): Error: Reader(1): Error: Reader(): Error: Reader(): Error: Reader(sig): Error: Reader(): Error: ASN1.bitString: non-zero amount of leftover bits':
              ['pkits/smime/SignedInvalidDSASignatureTest6.eml'],
            'CMS.signed: Reader(): Error: Reader(certificates): Error: Reader(1): Error: Reader(): Error: Reader(): Error: Reader(tbs): Error: Reader(serial): Error: Reader(): Error: negative values not allowed':
              ['pkits/smime/SignedInvalidNegativeSerialNumberTest15.eml'],
            'CMS.signed: Reader(): Error: Reader(crls): Error: Reader(0): Error: Reader(): Error: Reader(): Error: Reader(signatureValue): Error: Reader(): Error: ASN1.bitString: non-zero amount of leftover bits':
              ['pkits/smime/SignedInvalidBadCRLSignatureTest4.eml'],
          },
        },
        pathDiscovery: {
          total: 75,
          contentInfo: 71,
          signedData: 71,
          mismatch: [],
          errors: {
            'eml: invalid base64 CMS part': [
              'path-discovery/Path Discovery Test Suite/smime/SignedBasicHTTPURIPathDiscoveryOU1EE1.eml',
              'path-discovery/Path Discovery Test Suite/smime/SignedBasicHTTPURIPathDiscoveryOU1EE2.eml',
              'path-discovery/Path Discovery Test Suite/smime/SignedBasicHTTPURIPathDiscoveryOU1EE3.eml',
              'path-discovery/Path Discovery Test Suite/smime/SignedBasicHTTPURIPathDiscoveryOU1EE4.eml',
            ],
          },
        },
      }
    );
  });
  should('certificate fixture extensions decode in current support buckets', () => {
    const decoded: Record<string, number> = {};
    const decodeErrors: Record<string, string[]> = {};
    const extensionErrors: Record<string, string[]> = {};
    let extensionOk = 0;
    for (const name of certFixtureNames()) {
      try {
        const cert = X509.decode(read(name));
        count(decoded, cert.tbs.spki.algorithm.algorithm);
        try {
          X509.extensions(cert);
          extensionOk++;
        } catch (e) {
          push(extensionErrors, e instanceof Error ? e.message : String(e), name);
        }
      } catch (e) {
        push(decodeErrors, e instanceof Error ? e.message : String(e), name);
      }
    }
    deepStrictEqual(
      {
        decoded: sorted(decoded),
        decodeErrors: sortedLists(decodeErrors),
        extensionOk,
        extensionErrors: sortedLists(extensionErrors),
      },
      {
        decoded: {
          DSA: 4,
          rsaEncryption: 476,
        },
        decodeErrors: {
          'Reader(): Error: Reader(sig): Error: Reader(): Error: ASN1.bitString: non-zero amount of leftover bits':
            ['pkits/certs/BadSignedCACert.crt', 'pkits/certs/InvalidDSASignatureTest6EE.crt'],
          'Reader(): Error: Reader(tbs): Error: Reader(serial): Error: Reader(): Error: negative values not allowed':
            ['pkits/certs/InvalidNegativeSerialNumberTest15EE.crt'],
        },
        extensionOk: 477,
        extensionErrors: {
          'Reader(): Error: Reader(list/0): Error: Reader(qualifiers): Error: Reader(list/0): Error: Reader(): Error: Reader(explicitText): DisplayText must contain 1..200 characters by RFC 5280 section 4.2.1.4':
            ['pkits/certs/UserNoticeQualifierTest19EE.crt'],
          'Reader(): policyMappings must not contain anyPolicy': [
            'pkits/certs/MappingFromanyPolicyCACert.crt',
            'pkits/certs/MappingToanyPolicyCACert.crt',
          ],
        },
      }
    );
  });
  should('PKITS 4.3 name chaining cases reach the trust anchor when NIST says valid', () => {
    const trust = read(path.join(PKITS, 'certs', 'TrustAnchorRootCertificate.crt'));
    const result = PKITS_CASES.filter((test) => test.section.startsWith('4.3.')).map((test) =>
      nistResult(test, trust)
    );
    deepStrictEqual(
      result,
      result.map((r) => ({
        ...r,
        actual: r.expected,
        error: r.expected === 'pass' ? undefined : r.error,
      }))
    );
  });
  should('selected PKITS path validation cases match NIST expected results', () => {
    const trust = read(path.join(PKITS, 'certs', 'TrustAnchorRootCertificate.crt'));
    const result = PKITS_CASES.map((test) => nistResult(test, trust));
    // CRL/revocation processing is intentionally out of scope for this offline CMS verifier.
    deepStrictEqual(
      result
        .filter((r) => PKITS_UNSUPPORTED_REVOCATION[r.section])
        .map((r) => ({ ...r, unsupported: PKITS_UNSUPPORTED_REVOCATION[r.section] })),
      [
        {
          section: '4.5.2',
          title: 'Invalid Basic Self-Issued Old With New Test2',
          expected: 'fail',
          actual: 'pass',
          chain: 4,
          error: undefined,
          unsupported:
            'PKITS.pdf section 4.5.2 fails only because the end-entity certificate has been revoked.',
        },
        {
          section: '4.5.5',
          title: 'Invalid Basic Self-Issued New With Old Test5',
          expected: 'fail',
          actual: 'pass',
          chain: 3,
          error: undefined,
          unsupported:
            'PKITS.pdf section 4.5.5 fails only because the end-entity certificate has been revoked.',
        },
        {
          section: '4.5.7',
          title: 'Invalid Basic Self-Issued CRL Signing Key Test7',
          expected: 'fail',
          actual: 'pass',
          chain: 3,
          error: undefined,
          unsupported:
            'PKITS.pdf section 4.5.7 fails only because the end-entity certificate has been revoked.',
        },
        {
          section: '4.7.4',
          title: 'Invalid keyUsage Critical cRLSign False Test4',
          expected: 'fail',
          actual: 'pass',
          chain: 3,
          error: undefined,
          unsupported: 'PKITS.pdf section 4.7.4 fails only because CRL validation needs cRLSign.',
        },
        {
          section: '4.7.5',
          title: 'Invalid keyUsage Not Critical cRLSign False Test5',
          expected: 'fail',
          actual: 'pass',
          chain: 3,
          error: undefined,
          unsupported: 'PKITS.pdf section 4.7.5 fails only because CRL validation needs cRLSign.',
        },
      ]
    );
    const supported = result.filter((r) => !PKITS_UNSUPPORTED_REVOCATION[r.section]);
    deepStrictEqual(
      supported,
      supported.map((r) => ({
        ...r,
        actual: r.expected,
        error: r.expected === 'pass' ? undefined : r.error,
      }))
    );
  });
});

should.runWhen(import.meta.url);
