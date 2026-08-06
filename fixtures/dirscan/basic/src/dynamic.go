// Synthetic fixture. Not a real server.
//
// Nothing resolvable: the HTML is assembled at runtime. This URI must produce a
// UNRESOLVED_URI diagnostic and must never produce a finding.
package main

import "fmt"

const uiURI = "ui://demo/dynamic"

func render(rows []string) string {
	out := "<div>"
	for _, r := range rows {
		out += fmt.Sprintf("<span>%s</span>", r)
	}
	return out + "</div>"
}
