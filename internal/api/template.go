package api

import (
	"html/template"
	"net/url"
	"strings"
)

// TemplateFuncs returns template functions for use in HTML templates.
func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"safeURL": safeURL,
	}
}

func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return "#"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "https" || scheme == "http" {
		return raw
	}
	return "#"
}
