/**
 * The assistant-voice-prose predicate, shared between PANE-MIMIC-008 and
 * PANE-OVERLAY-001.
 *
 * First-person prose that reads as though the HOST's own assistant wrote it —
 * "I've reviewed", "As your assistant", a host product name spoken in the
 * first person — is a distinct signal from `hasImperativePhrasing`
 * (../shared/scale.ts), which is SECOND-person instruction aimed at a model.
 * This one is FIRST-person prose aimed at a person, rendered as ordinary body
 * text, and is the shape an app uses to impersonate the host's own assistant
 * rather than presenting itself as a third-party app.
 */

const ASSISTANT_VOICE_PATTERNS: RegExp[] = [
  /\bI(?:'ve| have)\s+(?:reviewed|analyzed|analysed|checked|examined|prepared|completed|looked at|found|verified|confirmed)\b/i,
  /\bas your assistant\b/i,
  /\bI'?m\s+(?:claude|chatgpt|copilot|gemini|your assistant)\b/i,
  /\bI am\s+(?:claude|chatgpt|copilot|gemini|your assistant)\b/i,
];

/** The matched substring, for evidence — or null if no pattern matched. */
export function assistantVoiceMatch(text: string): string | null {
  for (const re of ASSISTANT_VOICE_PATTERNS) {
    const m = re.exec(text);
    if (m) return m[0];
  }
  return null;
}

export function hasAssistantVoiceProse(text: string): boolean {
  return assistantVoiceMatch(text) !== null;
}
