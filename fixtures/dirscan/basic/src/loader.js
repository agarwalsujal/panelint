// Synthetic fixture. Not a real server.
//
// Route (c): a readFile call with a literal, repo-relative path argument.
import { readFileSync } from "node:fs";

const html = readFileSync("templates/loaded.html", "utf8");

export const resource = {
  uri: "ui://demo/loaded",
  mimeType: "text/html;profile=mcp-app",
  text: html,
};
