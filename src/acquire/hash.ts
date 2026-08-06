/**
 * Content hashing.
 *
 * The protocol has NO integrity mechanism — no signature, hash, version, or
 * pinning field exists anywhere in the resource schema. A resource can change
 * between a scan and its execution with no signal to anyone. So a scan is a
 * point-in-time claim, and this hash is what that claim is about.
 *
 * The definition is a one-way door: the public directory, the drift re-scan,
 * and the disclosure process all key on it. From docs/DESIGN.md §7, verbatim:
 *
 *   sha256 over the UTF-8 bytes of the `text` field exactly as received, or
 *   over the decoded bytes of `blob`. No normalization, no whitespace
 *   stripping, no BOM removal. A `blob` and a `text` resource with identical
 *   decoded bytes produce identical hashes.
 *
 * Do not add normalization here to make two "equivalent" resources match. They
 * are different bytes, and the whole point of the hash is to say so.
 */

import { createHash } from 'node:crypto';

export interface HashInput {
  text?: string;
  /** base64, as it arrives on the wire. */
  blob?: string;
}

export function sha256Bytes(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function sha256Resource(input: HashInput): string {
  return sha256Bytes(resourceBytes(input));
}

/** The exact bytes a resource's hash is taken over. */
export function resourceBytes(input: HashInput): Buffer {
  if (input.blob !== undefined) {
    return Buffer.from(input.blob, 'base64');
  }
  return Buffer.from(input.text ?? '', 'utf8');
}

/**
 * A hash of the rule registry plus the pinned versions of the dependencies
 * whose data changes between patch releases.
 *
 * `tldts` bundles a Public Suffix List snapshot and `csp_evaluator`'s
 * JSONP/Angular allowlists change between patch versions, so the same content
 * hash yields different findings on different Panelint builds. For a product
 * whose central claim is point-in-time honesty that is not acceptable, so every
 * report carries this alongside the content hash.
 */
export function ruleEngineFingerprint(parts: {
  ruleIds: string[];
  panelintVersion: string;
  cspEvaluatorVersion: string;
  tldtsVersion: string;
  schemaVersion: string;
}): string {
  const canonical = JSON.stringify({
    rules: [...parts.ruleIds].sort(),
    panelint: parts.panelintVersion,
    csp_evaluator: parts.cspEvaluatorVersion,
    tldts: parts.tldtsVersion,
    schema: parts.schemaVersion,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16);
}
