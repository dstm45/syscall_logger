// Package build contient les fichiers généré pas bpf2go
package build

//go:generate go tool bpf2go -tags linux main ../internal/ebpf/main.ebpf.c
