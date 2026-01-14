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

func RestrictFilesAndDirectories(l Loader) error {
	config, err := LoadConfig("config.yaml")
	if err != nil {
		return err
	}
	var key [64]byte
	var value uint32
	for _, restrictedfile := range config.RestrictedFiles {
		key = [64]byte{}
		copy(key[:], []byte(restrictedfile))
		value = uint32(1)
		err = l.MainObject.RestrictedFiles.Update(key, value, ebpf.UpdateAny)
		if err != nil {
			return err
		}
	}
	for _, restrictedirectory := range config.RestrictedDirectories {
		key = [64]byte{}
		copy(key[:], []byte(restrictedirectory))
		value = uint32(1)
		err = l.MainObject.RestrictedDirectories.Update(key, value, ebpf.UpdateAny)
		if err != nil {
			return err
		}
	}
	return nil
}
