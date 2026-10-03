//go:build linux

// Package cgroup discovers the single unified cgroup v2 hierarchy used by
// LanPanel. It deliberately does not fall back to a hard-coded mountpoint.
package cgroup

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Topology struct {
	Mountpoint string
	Root       string
	Current    string
}

func Discover() (Topology, error) {
	mounts, legacy, err := parseMountInfo("/proc/self/mountinfo")
	if err != nil {
		return Topology{}, err
	}
	if legacy {
		return Topology{}, fmt.Errorf("legacy cgroup v1 mounts are present")
	}
	if len(mounts) != 1 {
		return Topology{}, fmt.Errorf("unified cgroup v2 topology is ambiguous: %d root mounts", len(mounts))
	}
	current, err := parseCurrent("/proc/self/cgroup")
	if err != nil {
		return Topology{}, err
	}
	return Topology{Mountpoint: mounts[0].Mountpoint, Root: mounts[0].Root, Current: filepath.Join(mounts[0].Mountpoint, strings.TrimPrefix(current, "/"))}, nil
}

func ResolveRoot(root string) (string, error) {
	if root != "" && root != "/sys/fs/cgroup" {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return "", fmt.Errorf("cgroup root is invalid")
		}
		return root, nil
	}
	topology, err := Discover()
	if err != nil {
		return "", err
	}
	if topology.Root != "/" {
		return "", fmt.Errorf("unified cgroup v2 mount root is %q, want /", topology.Root)
	}
	return topology.Mountpoint, nil
}

func parseMountInfo(path string) ([]struct{ Root, Mountpoint string }, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("read cgroup mount topology: %w", err)
	}
	defer func() { _ = file.Close() }()
	var result []struct{ Root, Mountpoint string }
	legacy := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := slices.Index(fields, "-")
		if separator < 6 || separator+1 >= len(fields) {
			continue
		}
		if fields[separator+1] == "cgroup" {
			legacy = true
			continue
		}
		if separator+3 > len(fields) || fields[separator+1] != "cgroup2" {
			continue
		}
		root, err := unescape(fields[3])
		if err != nil {
			return nil, false, err
		}
		mountpoint, err := unescape(fields[4])
		if err != nil {
			return nil, false, err
		}
		result = append(result, struct{ Root, Mountpoint string }{Root: root, Mountpoint: mountpoint})
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	return result, legacy, nil
}

func parseCurrent(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read current cgroup identity: %w", err)
	}
	current := ""
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		if current != "" {
			return "", fmt.Errorf("unified cgroup identity is duplicated")
		}
		current = strings.TrimPrefix(line, "0::")
	}
	if current == "" || filepath.Clean(current) != current || !strings.HasPrefix(current, "/") || strings.Contains(current, "..") {
		return "", fmt.Errorf("unified cgroup identity is invalid")
	}
	return current, nil
}

func unescape(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) || value[index+1] < '0' || value[index+1] > '7' || value[index+2] < '0' || value[index+2] > '7' || value[index+3] < '0' || value[index+3] > '7' {
			return "", fmt.Errorf("cgroup mount path escape is invalid")
		}
		result.WriteByte((value[index+1]-'0')*64 + (value[index+2]-'0')*8 + value[index+3] - '0')
		index += 3
	}
	return result.String(), nil
}
