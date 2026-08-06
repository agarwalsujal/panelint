// Synthetic fixture. `vendor/` is on the deny list in src/safe/paths.ts, so this
// file must never be walked and `ui://vendored/never-seen` must never appear in
// a ResourceSet.
export const uri = "ui://vendored/never-seen";
export const mime = "text/html;profile=mcp-app";
