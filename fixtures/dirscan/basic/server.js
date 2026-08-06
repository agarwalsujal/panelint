// Synthetic fixture. Not a real server.
//
// Route (a): the declared URI's path tail matches a sibling file on disk.
const MIME = "text/html;profile=mcp-app";

export function register(server) {
  server.registerAppResource({
    uri: "ui://demo/board.html",
    mimeType: MIME,
    name: "board",
  });
}
