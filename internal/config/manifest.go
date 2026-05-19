package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const ManifestVersion = 1

type Manifest struct {
	Version        int       `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	Detector       string    `json:"detector"`
	RequestedSince time.Time `json:"requested_since"`
	RequestedUntil time.Time `json:"requested_until"`
	Orgs           []string  `json:"orgs"`
	Repos          []string  `json:"repos"`
}

func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest %s: %w", path, err)
	}

	return &manifest, nil
}

func SaveManifest(path string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create manifest dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write manifest %s: %w", path, err)
	}

	return nil
}

func (m Manifest) CanonicalHash() (string, error) {
	type canonicalManifest struct {
		Version        int      `json:"version"`
		Detector       string   `json:"detector"`
		RequestedSince string   `json:"requested_since"`
		RequestedUntil string   `json:"requested_until"`
		Orgs           []string `json:"orgs"`
		Repos          []string `json:"repos"`
	}

	orgs := append([]string(nil), m.Orgs...)
	repos := append([]string(nil), m.Repos...)
	slices.Sort(orgs)
	slices.Sort(repos)

	payload := canonicalManifest{
		Version:        m.Version,
		Detector:       m.Detector,
		RequestedSince: m.RequestedSince.UTC().Format(time.RFC3339),
		RequestedUntil: m.RequestedUntil.UTC().Format(time.RFC3339),
		Orgs:           orgs,
		Repos:          repos,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal canonical manifest: %w", err)
	}

	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
