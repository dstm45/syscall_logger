package handler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	RestrictedDirectories []string `yaml:"restricted_directories"`
	RestrictedFiles       []string `yaml:"restricted_files"`
}

func checkpath(path string) (string, error) {
	absolutePath := filepath.Clean(path)
	absolutePath, err := filepath.Abs(absolutePath)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(absolutePath)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%s n'existe pas. Err: %s", path, err)
	} else if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s n'est pas un fichier. Err: %s", path, err)
	}
	return absolutePath, nil
}

func LoadConfig(path string) (*Config, error) {
	newPath, err := checkpath(path)
	if err != nil {
		return nil, err
	}
	yamlConfig, err := os.ReadFile(newPath)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(yamlConfig, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
