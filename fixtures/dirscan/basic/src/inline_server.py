# Synthetic fixture. Not a real server.
#
# Route (b): the HTML lives in a triple-quoted literal in the declaring file.

BOARD_HTML = """<!DOCTYPE html>
<html>
  <body><p id="inline">inline literal</p></body>
</html>"""

RESOURCES = {
    "ui://demo/inline": {
        "mimeType": "text/html;profile=mcp-app",
        "html": BOARD_HTML,
    }
}
