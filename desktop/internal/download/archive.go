package download

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ExtractOptions struct {
	MaxFiles int
	MaxBytes int64
}

func (o ExtractOptions) normalized() ExtractOptions {
	if o.MaxFiles <= 0 {
		o.MaxFiles = 20_000
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 2 << 30
	}
	return o
}

func ExtractZip(archivePath, destination string, opts ExtractOptions) error {
	opts = opts.normalized()
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer reader.Close()
	if len(reader.File) > opts.MaxFiles {
		return fmt.Errorf("archive has %d files; limit is %d", len(reader.File), opts.MaxFiles)
	}
	var total int64
	for _, item := range reader.File {
		if item.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive contains symlink %q", item.Name)
		}
		target, err := safeTarget(destination, item.Name)
		if err != nil {
			return err
		}
		if item.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		total += int64(item.UncompressedSize64)
		if total > opts.MaxBytes {
			return fmt.Errorf("archive expands beyond %d-byte limit", opts.MaxBytes)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := item.Open()
		if err != nil {
			return err
		}
		mode := item.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, io.LimitReader(src, opts.MaxBytes+1))
		closeErr := dst.Close()
		src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func ExtractTarGz(archivePath, destination string, opts ExtractOptions) error {
	opts = opts.normalized()
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := 0
	var total int64
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		files++
		if files > opts.MaxFiles {
			return fmt.Errorf("archive has more than %d entries", opts.MaxFiles)
		}
		if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return fmt.Errorf("archive contains link %q", header.Name)
		}
		target, err := safeTarget(destination, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			total += header.Size
			if total > opts.MaxBytes {
				return fmt.Errorf("archive expands beyond %d-byte limit", opts.MaxBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			dst, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(dst, io.LimitReader(tr, header.Size))
			closeErr := dst.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("archive entry %q has unsupported type %d", header.Name, header.Typeflag)
		}
	}
	return nil
}

func safeTarget(root, name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("archive entry has empty path")
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(rootAbs, clean)
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path escapes destination: %q", name)
	}
	return target, nil
}
