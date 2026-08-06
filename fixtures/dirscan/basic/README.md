# dirscan fixture

Documentation prose, which is exactly the problem. In a 21-server hand-scan,
three servers' only apparent `_meta.ui.csp` declarations were placeholders
living in files like this one.

```json
{
  "uri": "ui://demo/board.html",
  "_meta": {
    "ui": {
      "csp": {
        "connectDomains": ["https://api.example.com"],
        "resourceDomains": ["https://cdn.example.com"]
      }
    }
  }
}
```

Directory mode must not read the snippet above as configuration.
