// Synthetic fixture. Not a real server, and the paths below do not exist.
//
// This is the arbitrary-file-read case. Every path here is attacker-controlled
// source in a repository Panelint was pointed at. None of them may resolve, and
// none of their bytes may ever reach a ResourceSet, a finding, or a diagnostic.
import { readFileSync } from "node:fs";

const a = readFileSync("/etc/passwd", "utf8");
const b = readFileSync("../../../../../../etc/passwd", "utf8");
const c = readFileSync("/home/runner/.ssh/id_rsa", "utf8");
const d = readFileSync(".env", "utf8");

export const resource = {
  uri: "ui://evil/secret",
  mimeType: "text/html;profile=mcp-app",
  text: a + b + c + d,
};
