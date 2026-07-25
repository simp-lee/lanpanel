package appconfig

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadBytes(data []byte) (Config, error) {
	var cfg Config

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode app config yaml: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, fmt.Errorf("decode app config yaml: multiple YAML documents are not supported")
	} else if err != io.EOF {
		return Config{}, fmt.Errorf("decode app config yaml: %w", err)
	}

	cfg.applyDefaults()
	cfg.normalize()
	if err := cfg.ValidateForExposurePlan(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read app config file: %w", err)
	}

	return LoadBytes(data)
}
