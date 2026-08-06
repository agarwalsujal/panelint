/**
 * `_meta.ui` validation and resolution.
 *
 * PANE-SCHEMA-001, -002, -004, -005 and -006 all derive from a SINGLE
 * `allErrors: true` validation, mapped by `(instancePath, keyword)`. Three rules
 * writing three validators is how they drift.
 *
 * The import is `Ajv2020` from `ajv/dist/2020`. The default `ajv` export cannot
 * compile the vendored schema — it throws
 *   no schema with key or ref "https://json-schema.org/draft/2020-12/schema"
 * because the schema is `$schema: draft/2020-12` with `$defs`. test/parse.test.ts
 * regression-locks that, so a dependency bump cannot quietly change the answer.
 */

import Ajv2020Import from 'ajv/dist/2020.js';
import type { AnySchema, ErrorObject, Options, ValidateFunction } from 'ajv';

/**
 * ajv ships CommonJS, so under NodeNext the class arrives either as the module
 * namespace or under `.default` depending on the interop path. Both shapes are
 * handled here once rather than at each construction site.
 */
type AjvConstructor = new (opts?: Options) => { compile(schema: AnySchema): ValidateFunction };
const Ajv2020: AjvConstructor =
  (Ajv2020Import as unknown as { default?: AjvConstructor }).default ??
  (Ajv2020Import as unknown as AjvConstructor);
import { readFileSync } from 'node:fs';
import type { UIResourceMeta, UIToolMeta } from '../types.js';

export interface MetaValidator {
  resource: ValidateFunction;
  tool: ValidateFunction;
  schemaVersion: string;
}

/** Field sets, asserted against the 2026-01-26 Stable spec text, not merely
 * against the generated schema — which tracks `main` and carries draft-only
 * constructs (docs/SPEC-REFERENCE.md, the boxed warning at the top). */
export const CSP_FIELDS = Object.freeze([
  'connectDomains',
  'resourceDomains',
  'frameDomains',
  'baseUriDomains',
] as const);

export const PERMISSION_FIELDS = Object.freeze([
  'camera',
  'microphone',
  'geolocation',
  'clipboardWrite',
] as const);

export const RESOURCE_META_FIELDS = Object.freeze([
  'csp',
  'permissions',
  'domain',
  'prefersBorder',
] as const);

/** `resourceDomains` is one knob that opens five directives. */
export const RESOURCE_DOMAIN_DIRECTIVES = Object.freeze([
  'img-src',
  'script-src',
  'style-src',
  'font-src',
  'media-src',
] as const);

let cached: MetaValidator | null = null;

export function createMetaValidator(schemaPath?: string): MetaValidator {
  if (cached && !schemaPath) return cached;

  const url = schemaPath ?? new URL('../../schema/schema.json', import.meta.url);
  const raw = JSON.parse(readFileSync(url as URL & string, 'utf8')) as Record<string, unknown>;
  const defs = (raw['$defs'] ?? raw['definitions']) as Record<string, object>;

  const ajv = new Ajv2020({ allErrors: true, strict: false, allowUnionTypes: true });

  const validator: MetaValidator = {
    resource: ajv.compile(defs['McpUiResourceMeta']!),
    tool: ajv.compile(defs['McpUiToolMeta']!),
    schemaVersion: readSchemaVersion(),
  };

  if (!schemaPath) cached = validator;
  return validator;
}

function readSchemaVersion(): string {
  try {
    return readFileSync(new URL('../../schema/VERSION', import.meta.url), 'utf8').trim();
  } catch {
    return 'unknown';
  }
}

/** One run. Callers map the errors; they do not re-validate. */
export function validateResourceMeta(v: MetaValidator, meta: unknown): ErrorObject[] {
  v.resource(meta);
  return (v.resource.errors ?? []).slice();
}

export function validateToolMeta(v: MetaValidator, meta: unknown): ErrorObject[] {
  v.tool(meta);
  return (v.tool.errors ?? []).slice();
}

/**
 * Resolve the two `_meta.ui` sources.
 *
 * From the ext-apps `McpUiAppResourceConfig` documentation, verbatim: the
 * `_meta.ui` field in the `resources/list` response "serves as a static default
 * for hosts to review at connection time. When the `resources/read` content item
 * also includes `_meta.ui`, the content-item value takes precedence."
 *
 * Both are retained on the UIResource. This function only computes the resolved
 * value; PANE-SPEC-010 compares the two, and it cannot do that if either is
 * discarded.
 */
export function resolveMeta(
  fromList: UIResourceMeta | undefined,
  fromRead: UIResourceMeta | undefined,
): UIResourceMeta | null {
  if (fromRead !== undefined) return fromRead;
  if (fromList !== undefined) return fromList;
  return null;
}

/** Extract `_meta.ui` from a raw `_meta` object, if present and object-shaped. */
export function extractUiMeta(rawMeta: unknown): UIResourceMeta | undefined {
  if (!rawMeta || typeof rawMeta !== 'object') return undefined;
  const ui = (rawMeta as Record<string, unknown>)['ui'];
  if (!ui || typeof ui !== 'object' || Array.isArray(ui)) return undefined;
  return ui as UIResourceMeta;
}

/** The deprecated flat key, kept separate so PANE-SPEC-006/011 can compare. */
export function extractFlatResourceUri(rawMeta: unknown): string | undefined {
  if (!rawMeta || typeof rawMeta !== 'object') return undefined;
  const v = (rawMeta as Record<string, unknown>)['ui/resourceUri'];
  return typeof v === 'string' ? v : undefined;
}

export function extractToolUiMeta(rawMeta: unknown): UIToolMeta | undefined {
  if (!rawMeta || typeof rawMeta !== 'object') return undefined;
  const ui = (rawMeta as Record<string, unknown>)['ui'];
  if (!ui || typeof ui !== 'object' || Array.isArray(ui)) return undefined;
  return ui as UIToolMeta;
}
