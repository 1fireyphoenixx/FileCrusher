// Package webui embeds the admin web UI assets.
package webui

import "embed"

// StaticFS holds embedded UI assets served by the HTTP server.
//go:embed static/*
var StaticFS embed.FS
