package artifactstest

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// XarTree builds an unsigned xar whose member names may contain "/" to place
// files in directories, the layout of a product archive's component packages.
func XarTree(t testing.TB, files map[string][]byte, extraTOC string) []byte {
	t.Helper()
	type node struct {
		children map[string]*node
		data     []byte
		file     bool
	}
	root := &node{children: map[string]*node{}}
	for name, data := range files {
		current := root
		parts := strings.Split(name, "/")
		for index, part := range parts {
			child, ok := current.children[part]
			if !ok {
				child = &node{children: map[string]*node{}}
				current.children[part] = child
			}
			if index == len(parts)-1 {
				child.data, child.file = data, true
			}
			current = child
		}
	}
	var heap, toc bytes.Buffer
	id := 0
	var write func(*node)
	write = func(parent *node) {
		names := make([]string, 0, len(parent.children))
		for name := range parent.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			child := parent.children[name]
			id++
			toc.WriteString(`<file id="` + strconv.Itoa(id) + `"><name>` + name + `</name>`)
			if child.file {
				offset := heap.Len()
				heap.Write(child.data)
				size := strconv.Itoa(len(child.data))
				toc.WriteString(`<type>file</type><data><length>` + size + `</length><offset>` + strconv.Itoa(offset) + `</offset><size>` + size + `</size><encoding style="application/octet-stream"/></data>`)
			} else {
				toc.WriteString(`<type>directory</type>`)
				write(child)
			}
			toc.WriteString(`</file>`)
		}
	}
	write(root)
	return xarBytes(t, []byte(`<xar><toc>`+extraTOC+toc.String()+`</toc></xar>`), heap.Bytes())
}

func xarBytes(t testing.TB, toc, heap []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	encoder := zlib.NewWriter(&compressed)
	if _, err := encoder.Write(toc); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 28)
	copy(header[:4], "xar!")
	binary.BigEndian.PutUint16(header[4:6], 28)
	binary.BigEndian.PutUint16(header[6:8], 1)
	binary.BigEndian.PutUint64(header[8:16], uint64(compressed.Len()))
	binary.BigEndian.PutUint64(header[16:24], uint64(len(toc)))
	return append(append(header, compressed.Bytes()...), heap...)
}

// CPIOEntry is one member of an odc cpio archive. A zero Mode is a regular
// file with permissions 0644.
type CPIOEntry struct {
	Name string
	Mode uint32
	Data []byte
}

// ModeRegular, ModeDirectory, and ModeSymlink are values for CPIOEntry.Mode.
const (
	ModeRegular   uint32 = 0o100644
	ModeDirectory uint32 = 0o040755
	ModeSymlink   uint32 = 0o120755
)

// GzipCPIO builds a gzip-compressed odc cpio archive, the format pkgbuild
// writes to a component package's Payload.
func GzipCPIO(t testing.TB, entries []CPIOEntry) []byte {
	t.Helper()
	var archive bytes.Buffer
	for index, entry := range append(append([]CPIOEntry(nil), entries...), CPIOEntry{Name: "TRAILER!!!", Mode: ModeRegular}) {
		mode := entry.Mode
		if mode == 0 {
			mode = ModeRegular
		}
		fmt.Fprintf(&archive, "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 0, index+1, mode, 0, 0, 1, 0, 0, len(entry.Name)+1, len(entry.Data))
		archive.WriteString(entry.Name)
		archive.WriteByte(0)
		archive.Write(entry.Data)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(archive.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}
