/**
 * The rule registry — GENERATED. Do not edit by hand.
 *
 * Regenerate with: node scripts/build-registry.mjs
 *
 * SARIF `rules[].id` is a public contract: the census directory keys on it and
 * disclosure emails cite it. IDs are permanent and never reused; a retired rule
 * keeps its ID with `status: 'retired'`. test/registry-docs.test.ts asserts this
 * file matches the tables in docs/RULES.md on id, class, severity and confidence,
 * so a doc and the code cannot silently diverge.
 */

import type { AnyRule } from '../types.js';

import { context001 } from './context/context-001.js';
import { context002 } from './context/context-002.js';
import { context003 } from './context/context-003.js';
import { context004 } from './context/context-004.js';
import { context005 } from './context/context-005.js';
import { context006 } from './context/context-006.js';
import { context007 } from './context/context-007.js';
import { context008 } from './context/context-008.js';
import { context009 } from './context/context-009.js';
import { context010 } from './context/context-010.js';
import { paneCsp001 } from './csp/csp-001-connect-wildcard.js';
import { paneCsp002 } from './csp/csp-002-resource-wildcard.js';
import { paneCsp003 } from './csp/csp-003-frame-domains.js';
import { paneCsp004 } from './csp/csp-004-base-uri-domains.js';
import { paneCsp005 } from './csp/csp-005-shared-hosting.js';
import { paneCsp006 } from './csp/csp-006-undeclared-origin.js';
import { paneCsp007 } from './csp/csp-007-jsonp-bypass.js';
import { paneCsp008 } from './csp/csp-008-publishable-cdn.js';
import { paneCsp009 } from './csp/csp-009-unused-connect-domain.js';
import { paneCsp010 } from './csp/csp-010-css-attribute-exfil.js';
import { paneCsp011 } from './csp/csp-011-opaque-frame.js';
import { paneCsp012 } from './csp/csp-012-cdn-script-no-integrity.js';
import { paneCsp013 } from './csp/csp-013-empty-csp.js';
import { dom001 } from './dom/dom-001.js';
import { dom002 } from './dom/dom-002.js';
import { exfil001 } from './exfil/exfil-001.js';
import { exfil002 } from './exfil/exfil-002.js';
import { exfil003 } from './exfil/exfil-003.js';
import { exfil004 } from './exfil/exfil-004.js';
import { exfil005 } from './exfil/exfil-005.js';
import { exfil006 } from './exfil/exfil-006.js';
import { exfil007 } from './exfil/exfil-007.js';
import { paneHidden001 } from './hidden/pane-hidden-001.js';
import { paneHidden002 } from './hidden/pane-hidden-002.js';
import { paneHidden003 } from './hidden/pane-hidden-003.js';
import { paneHidden004 } from './hidden/pane-hidden-004.js';
import { paneHidden005 } from './hidden/pane-hidden-005.js';
import { paneHidden006 } from './hidden/pane-hidden-006.js';
import { paneHidden007 } from './hidden/pane-hidden-007.js';
import { paneHidden008 } from './hidden/pane-hidden-008.js';
import { paneHidden009 } from './hidden/pane-hidden-009.js';
import { paneHidden010 } from './hidden/pane-hidden-010.js';
import { paneHidden011 } from './hidden/pane-hidden-011.js';
import { paneHidden012 } from './hidden/pane-hidden-012.js';
import { paneHidden013 } from './hidden/pane-hidden-013.js';
import { paneHidden014 } from './hidden/pane-hidden-014.js';
import { paneHidden015 } from './hidden/pane-hidden-015.js';
import { paneHidden016 } from './hidden/pane-hidden-016.js';
import { input001 } from './input/input-001.js';
import { input002 } from './input/input-002.js';
import { input003 } from './input/input-003.js';
import { input004 } from './input/input-004.js';
import { integrity001 } from './integrity/integrity-001.js';
import { integrity002 } from './integrity/integrity-002.js';
import { mimic001 } from './mimic/mimic-001.js';
import { mimic002 } from './mimic/mimic-002.js';
import { mimic003 } from './mimic/mimic-003.js';
import { mimic004 } from './mimic/mimic-004.js';
import { mimic005 } from './mimic/mimic-005.js';
import { mimic006 } from './mimic/mimic-006.js';
import { mimic007 } from './mimic/mimic-007.js';
import { mimic008 } from './mimic/mimic-008.js';
import { msg001 } from './msg/msg-001.js';
import { msg002 } from './msg/msg-002.js';
import { msg003 } from './msg/msg-003.js';
import { msg004 } from './msg/msg-004.js';
import { paneOverlay001 } from './overlay/pane-overlay-001.js';
import { paneOverlay002 } from './overlay/pane-overlay-002.js';
import { paneOverlay003 } from './overlay/pane-overlay-003.js';
import { sandbox001 } from './sandbox/sandbox-001.js';
import { sandbox002 } from './sandbox/sandbox-002.js';
import { sandbox003 } from './sandbox/sandbox-003.js';
import { sandbox004 } from './sandbox/sandbox-004.js';
import { sandbox005 } from './sandbox/sandbox-005.js';
import { sandbox006 } from './sandbox/sandbox-006.js';
import { sandbox007 } from './sandbox/sandbox-007.js';
import { paneSchema003 } from './schema/domain-shape.js';
import { paneSchema004 } from './schema/meta-schema.js';
import { paneSchema005 } from './schema/tool-meta.js';
import { paneSchema001, paneSchema002, paneSchema006 } from './schema/unknown-keys.js';
import { paneSpec003 } from './spec/content-present.js';
import { paneSpec008 } from './spec/domain-declared.js';
import { paneSpec007 } from './spec/extension-declaration.js';
import { paneSpec010 } from './spec/meta-divergence.js';
import { paneSpec002, paneSpec009 } from './spec/mime-type.js';
import { paneSpec004 } from './spec/parser-differential.js';
import { paneSpec005, paneSpec006, paneSpec011 } from './spec/tool-resource-link.js';
import { paneSpec001 } from './spec/uri.js';

/** Every rule Panelint knows about, in ID order. */
export const ALL_RULES: AnyRule[] = [
  context001,
  context002,
  context003,
  context004,
  context005,
  context006,
  context007,
  context008,
  context009,
  context010,
  paneCsp001,
  paneCsp002,
  paneCsp003,
  paneCsp004,
  paneCsp005,
  paneCsp006,
  paneCsp007,
  paneCsp008,
  paneCsp009,
  paneCsp010,
  paneCsp011,
  paneCsp012,
  paneCsp013,
  dom001,
  dom002,
  exfil001,
  exfil002,
  exfil003,
  exfil004,
  exfil005,
  exfil006,
  exfil007,
  paneHidden001,
  paneHidden002,
  paneHidden003,
  paneHidden004,
  paneHidden005,
  paneHidden006,
  paneHidden007,
  paneHidden008,
  paneHidden009,
  paneHidden010,
  paneHidden011,
  paneHidden012,
  paneHidden013,
  paneHidden014,
  paneHidden015,
  paneHidden016,
  input001,
  input002,
  input003,
  input004,
  integrity001,
  integrity002,
  mimic001,
  mimic002,
  mimic003,
  mimic004,
  mimic005,
  mimic006,
  mimic007,
  mimic008,
  msg001,
  msg002,
  msg003,
  msg004,
  paneOverlay001,
  paneOverlay002,
  paneOverlay003,
  sandbox001,
  sandbox002,
  sandbox003,
  sandbox004,
  sandbox005,
  sandbox006,
  sandbox007,
  paneSchema003,
  paneSchema004,
  paneSchema005,
  paneSchema001,
  paneSchema002,
  paneSchema006,
  paneSpec003,
  paneSpec008,
  paneSpec007,
  paneSpec010,
  paneSpec002,
  paneSpec009,
  paneSpec004,
  paneSpec005,
  paneSpec006,
  paneSpec011,
  paneSpec001,
].sort((a, b) => a.id.localeCompare(b.id)) as AnyRule[];

export const RULES_BY_ID: ReadonlyMap<string, AnyRule> = new Map(
  ALL_RULES.map((r) => [r.id, r] as const),
);

/** Rules that run for a given scan, honouring --experimental. */
export function selectRules(opts: { experimental?: boolean } = {}): AnyRule[] {
  return ALL_RULES.filter((r) => r.status !== 'retired')
    .filter((r) => (opts.experimental ? true : !r.experimental));
}
