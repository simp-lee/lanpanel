//go:build linux

package packages

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LinuxMonitor struct {
	cgroupRoot string
	procRoot   string
	interval   time.Duration
}

func NewLinuxMonitor() *LinuxMonitor {
	return &LinuxMonitor{cgroupRoot: "/sys/fs/cgroup/system.slice", procRoot: "/proc/net", interval: 25 * time.Millisecond}
}

func newTestLinuxMonitor(cgroupRoot, procRoot string, interval time.Duration) *LinuxMonitor {
	return &LinuxMonitor{cgroupRoot: cgroupRoot, procRoot: procRoot, interval: interval}
}

func (monitor *LinuxMonitor) Start(ctx context.Context, units, listeners []string) (context.Context, func() error, error) {
	if monitor == nil || !sortedUniqueUnits(units) || validateListeners(listeners) != nil || !filepath.IsAbs(monitor.cgroupRoot) || !filepath.IsAbs(monitor.procRoot) || monitor.interval <= 0 || monitor.interval > time.Second {
		return nil, nil, fmt.Errorf("package runtime monitor authority is invalid")
	}
	baseline, err := monitor.observe()
	if err != nil {
		return nil, nil, err
	}
	for _, unit := range units {
		if baseline.units[unit] {
			return nil, nil, fmt.Errorf("affected package unit is active before transaction")
		}
	}
	for _, listener := range listeners {
		if baseline.listeners[listener] {
			return nil, nil, fmt.Errorf("affected package listener is bound before transaction")
		}
	}
	monitorCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var mu sync.Mutex
	var observedErr error
	go func() {
		defer close(done)
		ticker := time.NewTicker(monitor.interval)
		defer ticker.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-ticker.C:
				observation, err := monitor.observe()
				if err == nil && !equalBoolMap(observation.units, baseline.units) {
					err = fmt.Errorf("package maintainer script changed the complete unit/cgroup inventory")
				}
				if err == nil && !equalBoolMap(observation.listeners, baseline.listeners) {
					err = fmt.Errorf("package maintainer script changed the complete bound-listener inventory")
				}
				if err != nil {
					mu.Lock()
					observedErr = err
					mu.Unlock()
					cancel()
					return
				}
			}
		}
	}()
	var once sync.Once
	stop := func() error {
		once.Do(func() {
			observation, err := monitor.observe()
			if err == nil && !equalBoolMap(observation.units, baseline.units) {
				err = fmt.Errorf("package maintainer script changed the complete unit/cgroup inventory")
			}
			if err == nil && !equalBoolMap(observation.listeners, baseline.listeners) {
				err = fmt.Errorf("package maintainer script changed the complete bound-listener inventory")
			}
			if err != nil {
				mu.Lock()
				observedErr = errors.Join(observedErr, err)
				mu.Unlock()
			}
			cancel()
			<-done
		})
		mu.Lock()
		defer mu.Unlock()
		return observedErr
	}
	return monitorCtx, stop, nil
}

type monitorObservation struct {
	units     map[string]bool
	listeners map[string]bool
}

func (monitor *LinuxMonitor) observe() (monitorObservation, error) {
	observation := monitorObservation{units: map[string]bool{}, listeners: map[string]bool{}}
	entries, err := os.ReadDir(monitor.cgroupRoot)
	if err != nil {
		return monitorObservation{}, fmt.Errorf("enumerate systemd package monitor cgroups: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !unitPattern.MatchString(entry.Name()) {
			continue
		}
		active, err := cgroupHasProcesses(filepath.Join(monitor.cgroupRoot, entry.Name(), "cgroup.procs"))
		if err != nil {
			return monitorObservation{}, err
		}
		observation.units[entry.Name()] = active
	}
	bound, err := readBoundListeners(monitor.procRoot)
	if err != nil {
		return monitorObservation{}, err
	}
	observation.listeners = bound
	return observation, nil
}

func equalBoolMap(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func cgroupHasProcesses(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("observe package unit cgroup: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return false, nil
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return false, fmt.Errorf("package unit cgroup process inventory is malformed")
	}
	return true, nil
}

func readBoundListeners(root string) (map[string]bool, error) {
	result := map[string]bool{}
	for _, table := range []struct {
		name, protocol string
		tcp            bool
	}{{"tcp", "tcp", true}, {"tcp6", "tcp", true}, {"udp", "udp", false}, {"udp6", "udp", false}} {
		file, err := os.Open(filepath.Join(root, table.name))
		if err != nil {
			return nil, fmt.Errorf("observe package listener table: %w", err)
		}
		scanner := bufio.NewScanner(file)
		line := 0
		for scanner.Scan() {
			line++
			if line == 1 {
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				_ = file.Close()
				return nil, fmt.Errorf("package listener table is malformed")
			}
			if table.tcp && fields[3] != "0A" {
				continue
			}
			if !table.tcp && !zeroRemoteAddress(fields[2]) {
				continue
			}
			_, portHex, found := strings.Cut(fields[1], ":")
			port, parseErr := strconv.ParseUint(portHex, 16, 16)
			if !found || parseErr != nil || port == 0 {
				_ = file.Close()
				return nil, fmt.Errorf("package listener table contains an invalid address")
			}
			result[table.protocol+"/"+strconv.FormatUint(port, 10)] = true
		}
		scanErr, closeErr := scanner.Err(), file.Close()
		if scanErr != nil || closeErr != nil {
			return nil, errors.Join(scanErr, closeErr)
		}
	}
	return result, nil
}

func zeroRemoteAddress(value string) bool {
	address, port, found := strings.Cut(value, ":")
	if !found || port != "0000" || address == "" {
		return false
	}
	for _, character := range address {
		if character != '0' {
			return false
		}
	}
	return true
}
