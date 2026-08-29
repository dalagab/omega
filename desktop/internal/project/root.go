package project

import (
	"errors"
	"os"
	"path/filepath"
)

// FindRoot resolves a standalone DeltaScope source root. It accepts a file or
// directory start point and walks upward until the runtime contract and Python
// entry point are both present.
func FindRoot(start string) (string, error) {
	if start == "" {
		var err error
		start, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	if info, statErr := os.Stat(abs); statErr == nil && !info.IsDir() {
		abs = filepath.Dir(abs)
	}
	for {
		contract := filepath.Join(abs, "deltascope", "runtime-contract.json")
		entry := filepath.Join(abs, "tools", "security", "deltascope.py")
		if fileExists(contract) && fileExists(entry) {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			break
		}
		abs = parent
	}
	return "", errors.New("could not locate DeltaScope source root")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
