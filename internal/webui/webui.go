package webui

import "embed"

//go:embed static/*
var StaticFS embed.FS
