// Package archive validates and extracts release-declared exact archive members.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"lanpanel/internal/filetxn"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

type Format string

const (
	Tar     Format = "tar"
	TarGzip Format = "tar_gzip"
	Zip     Format = "zip"

	tarBlockSize      = 512
	tarRecordSize     = 20 * tarBlockSize // GNU tar's explicit --blocking-factor=20 contract.
	maximumTarPadding = tarRecordSize - 2*tarBlockSize
)

type Member struct {
	Path                 string
	MaximumBytes         int64
	MaximumPhysicalBytes int64
	Destination          string
	Metadata             filetxn.Metadata
}

type Spec struct {
	Format                Format
	MaximumArchiveBytes   int64
	MaximumExtractedBytes int64
	MaximumMembers        int
	Members               []Member
}

func Extract(data []byte, spec Spec) (map[string][]byte, error) {
	expected, err := validateSpec(data, spec)
	if err != nil {
		return nil, err
	}
	switch spec.Format {
	case Tar:
		return extractTarExact(data, expected, spec.MaximumExtractedBytes)
	case TarGzip:
		input := bytes.NewReader(data)
		compressed, err := gzip.NewReader(input)
		if err != nil {
			return nil, fmt.Errorf("open gzip archive")
		}
		compressed.Multistream(false)
		uncompressed, err := io.ReadAll(io.LimitReader(compressed, spec.MaximumExtractedBytes+(1<<20)+1))
		closeErr := compressed.Close()
		if err != nil || closeErr != nil || input.Len() != 0 || int64(len(uncompressed)) > spec.MaximumExtractedBytes+(1<<20) {
			return nil, fmt.Errorf("read bounded complete gzip stream")
		}
		return extractTarExact(uncompressed, expected, spec.MaximumExtractedBytes)
	case Zip:
		return extractZip(data, expected, spec.MaximumExtractedBytes)
	default:
		return nil, fmt.Errorf("archive format is unknown")
	}
}

func validateSpec(data []byte, spec Spec) (map[string]Member, error) {
	if len(data) == 0 || spec.MaximumArchiveBytes <= 0 || int64(len(data)) > spec.MaximumArchiveBytes || spec.MaximumExtractedBytes <= 0 || spec.MaximumMembers <= 0 || spec.MaximumMembers > 1024 || len(spec.Members) == 0 || len(spec.Members) > spec.MaximumMembers {
		return nil, fmt.Errorf("archive bytes or manifest bounds are invalid")
	}
	members := append([]Member(nil), spec.Members...)
	slices.SortFunc(members, func(left, right Member) int { return strings.Compare(left.Path, right.Path) })
	expected := map[string]Member{}
	casefold := map[string]bool{}
	for _, member := range members {
		folded := strings.ToLower(member.Path)
		if !validMemberPath(member.Path) || member.MaximumBytes < 0 || member.MaximumBytes > spec.MaximumExtractedBytes || member.MaximumPhysicalBytes <= 0 || !filepath.IsAbs(member.Destination) || filepath.Clean(member.Destination) != member.Destination || member.Metadata.Mode.Perm() == 0 || member.Metadata.Mode&0o7000 != 0 || expected[member.Path].Path != "" || casefold[folded] {
			return nil, fmt.Errorf("archive member manifest is invalid or colliding")
		}
		expected[member.Path] = member
		casefold[folded] = true
	}
	return expected, nil
}

func extractTarExact(data []byte, expected map[string]Member, maximumTotal int64) (map[string][]byte, error) {
	reader := bytes.NewReader(data)
	result, err := extractTar(reader, expected, maximumTotal)
	if err != nil {
		return nil, err
	}
	if reader.Len() != 0 {
		if reader.Len() > maximumTarPadding || reader.Len()%tarBlockSize != 0 {
			return nil, fmt.Errorf("tar archive contains trailing bytes")
		}
		padding, readErr := io.ReadAll(reader)
		allZero := true
		for _, value := range padding {
			if value != 0 {
				allZero = false
				break
			}
		}
		if readErr != nil || !allZero {
			return nil, fmt.Errorf("tar archive contains trailing bytes")
		}
	}
	return result, nil
}

func extractTar(reader io.Reader, expected map[string]Member, maximumTotal int64) (map[string][]byte, error) {
	archive := tar.NewReader(io.LimitReader(reader, maximumTotal+(1<<20)))
	result := map[string][]byte{}
	var total int64
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar archive")
		}
		member, known := expected[header.Name]
		if !known || !validMemberPath(header.Name) || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > member.MaximumBytes || len(header.PAXRecords) != 0 || header.Format == tar.FormatPAX || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Devmajor != 0 || header.Devminor != 0 || header.Mode&0o7000 != 0 {
			return nil, fmt.Errorf("tar archive contains unexpected type, metadata, member, or size")
		}
		physical, physicalOK := tarPhysicalBytes(header.Size)
		if !physicalOK || physical > member.MaximumPhysicalBytes {
			return nil, fmt.Errorf("tar archive contains unexpected type, metadata, member, or size")
		}
		if _, duplicate := result[header.Name]; duplicate {
			return nil, fmt.Errorf("tar archive contains duplicate member")
		}
		if total+header.Size > maximumTotal {
			return nil, fmt.Errorf("tar archive exceeds total extracted bound")
		}
		content, err := io.ReadAll(io.LimitReader(archive, member.MaximumBytes+1))
		if err != nil || int64(len(content)) != header.Size {
			return nil, fmt.Errorf("tar member is truncated or oversized")
		}
		result[header.Name] = content
		total += int64(len(content))
	}
	return requireComplete(result, expected)
}

func extractZip(data []byte, expected map[string]Member, maximumTotal int64) (map[string][]byte, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(archive.File) > 1024 || archive.Comment != "" {
		return nil, fmt.Errorf("open bounded zip archive")
	}
	result := map[string][]byte{}
	var total int64
	for _, file := range archive.File {
		member, known := expected[file.Name]
		mode := file.Mode()
		if !known || !validMemberPath(file.Name) || file.NonUTF8 || file.Comment != "" || len(file.Extra) != 0 || mode&0o7000 != 0 || !mode.IsRegular() || file.UncompressedSize64 > uint64(member.MaximumBytes) || file.CompressedSize64 > uint64(member.MaximumPhysicalBytes) || file.UncompressedSize64 > uint64(maximumTotal) {
			return nil, fmt.Errorf("zip archive contains unexpected type, metadata, member, or size")
		}
		if _, duplicate := result[file.Name]; duplicate {
			return nil, fmt.Errorf("zip archive contains duplicate member")
		}
		if total+int64(file.UncompressedSize64) > maximumTotal {
			return nil, fmt.Errorf("zip archive exceeds total extracted bound")
		}
		reader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open zip member")
		}
		content, readErr := io.ReadAll(io.LimitReader(reader, member.MaximumBytes+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || uint64(len(content)) != file.UncompressedSize64 {
			return nil, fmt.Errorf("zip member is truncated, corrupt, or oversized")
		}
		result[file.Name] = content
		total += int64(len(content))
	}
	return requireComplete(result, expected)
}

func CommitMember(ctx context.Context, store *filetxn.Store, parents filetxn.DirectoryPolicy, existing *filetxn.Metadata, disposition filetxn.Disposition, extracted map[string][]byte, spec Spec, member string) (filetxn.Result, error) {
	if store == nil || !validMemberPath(member) || len(extracted) == 0 || len(extracted) > 1024 {
		return filetxn.Result{}, fmt.Errorf("archive activation authority is invalid")
	}
	content, exists := extracted[member]
	declaration, declared := declaredMember(spec.Members, member)
	if !exists || !declared || int64(len(content)) > declaration.MaximumBytes {
		return filetxn.Result{}, fmt.Errorf("archive activation member is missing")
	}
	request := filetxn.Request{Path: declaration.Destination, Parents: parents, Existing: existing, New: declaration.Metadata, MaxBytes: declaration.MaximumBytes}
	return store.Put(ctx, request, content, disposition)
}

func declaredMember(members []Member, name string) (Member, bool) {
	for _, member := range members {
		if member.Path == name {
			return member, true
		}
	}
	return Member{}, false
}

func tarPhysicalBytes(size int64) (int64, bool) {
	if size < 0 || size > 1<<63-1-511 {
		return 0, false
	}
	return ((size + 511) / 512) * 512, true
}

func requireComplete(result map[string][]byte, expected map[string]Member) (map[string][]byte, error) {
	if len(result) != len(expected) {
		return nil, fmt.Errorf("archive omits a release-declared member")
	}
	return result, nil
}

func validMemberPath(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || strings.ContainsAny(value, "\x00\r\n") || path.Clean(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}
