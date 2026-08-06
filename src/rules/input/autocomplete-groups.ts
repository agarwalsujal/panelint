/**
 * WHATWG `autocomplete` field-name tokens, grouped as PANE-INPUT-001/002 need
 * them: payment, address, and identity. Shared so both rules agree on exactly
 * one definition of "sensitive."
 *
 * Only the FIELD-NAME token is listed — never the modifier tokens
 * (`shipping`, `billing`, `home`, `work`, `mobile`, `section-*`) that can
 * precede it in a multi-token value like `autocomplete="shipping street-address"`.
 * A modifier alone says nothing about sensitivity; the field-name token is what
 * tells the browser what to autofill.
 *
 * Source: WHATWG HTML Standard §form-control-infrastructure, "Autofill field
 * name" categories.
 */

export const PAYMENT_TOKENS: ReadonlySet<string> = new Set([
  'cc-name',
  'cc-given-name',
  'cc-additional-name',
  'cc-family-name',
  'cc-number',
  'cc-exp',
  'cc-exp-month',
  'cc-exp-year',
  'cc-csc',
  'cc-type',
  'transaction-currency',
  'transaction-amount',
]);

export const ADDRESS_TOKENS: ReadonlySet<string> = new Set([
  'street-address',
  'address-line1',
  'address-line2',
  'address-line3',
  'address-level1',
  'address-level2',
  'address-level3',
  'address-level4',
  'country',
  'country-name',
  'postal-code',
]);

export const IDENTITY_TOKENS: ReadonlySet<string> = new Set([
  'name',
  'honorific-prefix',
  'given-name',
  'additional-name',
  'family-name',
  'honorific-suffix',
  'nickname',
  'username',
  'new-password',
  'current-password',
  'one-time-code',
  'organization',
  'organization-title',
  'sex',
  'tel',
  'tel-country-code',
  'tel-national',
  'tel-area-code',
  'tel-local',
  'tel-extension',
  'email',
  'impp',
  'bday',
  'bday-day',
  'bday-month',
  'bday-year',
]);

export const SENSITIVE_AUTOCOMPLETE_TOKENS: ReadonlySet<string> = new Set([
  ...PAYMENT_TOKENS,
  ...ADDRESS_TOKENS,
  ...IDENTITY_TOKENS,
]);

/** The autofill field-name token(s) in an `autocomplete` attribute value, if any are sensitive. */
export function sensitiveAutocompleteTokens(value: string): string[] {
  return value
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((tok) => SENSITIVE_AUTOCOMPLETE_TOKENS.has(tok));
}

export function autocompleteGroup(token: string): 'payment' | 'address' | 'identity' | null {
  if (PAYMENT_TOKENS.has(token)) return 'payment';
  if (ADDRESS_TOKENS.has(token)) return 'address';
  if (IDENTITY_TOKENS.has(token)) return 'identity';
  return null;
}
