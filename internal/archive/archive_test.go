package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"lanpanel/internal/filetxn"
	"strings"
	"testing"
)

func TestArchiveExtractsOnlyExactDeclaredRegularMembers(t *testing.T) {
	var tarBytes bytes.Buffer
	writer := tar.NewWriter(&tarBytes)
	for name, content := range map[string]string{"bin/tool": "tool", "NOTICE": "notice"} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = writer.Write([]byte(content))
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	spec := Spec{Format: Tar, MaximumArchiveBytes: 4096, MaximumExtractedBytes: 1024, MaximumMembers: 2, Members: []Member{testMember("NOTICE", 64), testMember("bin/tool", 64)}}
	extracted, err := Extract(tarBytes.Bytes(), spec)
	if err != nil || string(extracted["bin/tool"]) != "tool" || string(extracted["NOTICE"]) != "notice" {
		t.Fatalf("extracted=%v error=%v", extracted, err)
	}

	var zipBytes bytes.Buffer
	zipWriter := zip.NewWriter(&zipBytes)
	for name, content := range map[string]string{"bin/tool": "tool", "NOTICE": "notice"} {
		member, err := zipWriter.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = member.Write([]byte(content))
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	spec.Format = Zip
	if _, err := Extract(zipBytes.Bytes(), spec); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveRejectsCompressedPhysicalOverflowAndZipMetadata(t *testing.T) {
	var tarBytes bytes.Buffer
	tarWriter := tar.NewWriter(&tarBytes)
	content := []byte(strings.Repeat("x", 128))
	if err := tarWriter.WriteHeader(&tar.Header{Name: "bin/tool", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tarWriter.Write(content)
	_ = tarWriter.Close()
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	_, _ = gzipWriter.Write(tarBytes.Bytes())
	_ = gzipWriter.Close()
	member := testMember("bin/tool", 256)
	member.MaximumPhysicalBytes = 1
	if _, err := Extract(compressed.Bytes(), Spec{Format: TarGzip, MaximumArchiveBytes: 4096, MaximumExtractedBytes: 512, MaximumMembers: 1, Members: []Member{member}}); err == nil {
		t.Fatal("gzip archive physical overflow was accepted")
	}
	trailing := append(append([]byte(nil), compressed.Bytes()...), []byte("trailing")...)
	member.MaximumPhysicalBytes = 4096
	if _, err := Extract(trailing, Spec{Format: TarGzip, MaximumArchiveBytes: 8192, MaximumExtractedBytes: 512, MaximumMembers: 1, Members: []Member{member}}); err == nil {
		t.Fatal("gzip trailing stream data was accepted")
	}

	var zipBytes bytes.Buffer
	zipWriter := zip.NewWriter(&zipBytes)
	header := &zip.FileHeader{Name: "bin/tool", Method: zip.Store, Extra: []byte{1, 0, 0, 0}}
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write([]byte("tool"))
	_ = zipWriter.Close()
	if _, err := Extract(zipBytes.Bytes(), Spec{Format: Zip, MaximumArchiveBytes: 4096, MaximumExtractedBytes: 64, MaximumMembers: 1, Members: []Member{testMember("bin/tool", 8)}}); err == nil {
		t.Fatal("zip unsupported extra metadata was accepted")
	}
}

func TestArchiveRejectsLinksTraversalUnexpectedCollisionAndBounds(t *testing.T) {
	for name, header := range map[string]tar.Header{
		"link":       {Name: "bin/tool", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"},
		"traversal":  {Name: "../tool", Typeflag: tar.TypeReg},
		"special":    {Name: "bin/tool", Typeflag: tar.TypeChar},
		"setuid":     {Name: "bin/tool", Typeflag: tar.TypeReg, Mode: 0o4755},
		"unexpected": {Name: "other", Typeflag: tar.TypeReg},
	} {
		var data bytes.Buffer
		writer := tar.NewWriter(&data)
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		spec := Spec{Format: Tar, MaximumArchiveBytes: 4096, MaximumExtractedBytes: 64, MaximumMembers: 1, Members: []Member{testMember("bin/tool", 8)}}
		if _, err := Extract(data.Bytes(), spec); err == nil {
			t.Fatalf("hostile %s archive was accepted", name)
		}
	}
	if _, err := Extract([]byte("x"), Spec{Format: Tar, MaximumArchiveBytes: 1024, MaximumExtractedBytes: 1, MaximumMembers: 2, Members: []Member{testMember("A", 1), testMember("a", 1)}}); err == nil {
		t.Fatal("case-colliding archive manifest was accepted")
	}
}

func testMember(path string, maximum int64) Member {
	return Member{Path: path, MaximumBytes: maximum, MaximumPhysicalBytes: 1024, Destination: "/var/lib/lanpanel/archive/" + path, Metadata: filetxn.Metadata{Owner: filetxn.Owner{UID: 0, GID: 0}, Mode: 0o644}}
}
