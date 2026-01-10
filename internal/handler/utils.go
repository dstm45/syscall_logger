// Package handler contient tous les fonctions utilitaires
package handler

import (
	"strings"

	"github.com/cilium/ebpf"
)

func Int8ToString(arr [64]int8) string {
	b := make([]byte, 0, len(arr))

	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}

	return string(b)
}

func IsExcluded(arr [64]int8) bool {
	filepath := Int8ToString(arr)
	excludeDirs := []string{"/dev", "/proc", "/var", "/run"}
	for _, dir := range excludeDirs {
		if strings.Contains(filepath, dir) {
			return true
		}
	}
	return false
}

func RestrictFiles(l Loader) error {
	var key [64]byte
	copy(key[:], []byte("/home/monga/code/ebpf/syscall_logger/secret.txt"))
	value := uint32(1)
	err := l.MainObject.RestrictedFiles.Update(key, value, ebpf.UpdateAny)
	if err != nil {
		return err
	}
	return nil
}

func RestrictDirectories(l Loader) error {
	var key [64]byte
	copy(key[:], []byte("/home/monga/code/ebpf/syscall_logger"))
	value := uint32(1)
	err := l.MainObject.RestrictedDirectories.Update(key, value, ebpf.UpdateAny)
	if err != nil {
		return err
	}
	return nil
}
