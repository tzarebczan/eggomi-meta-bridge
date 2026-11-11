// Package media is the bridge's capped media cache (PROTOCOL.md section 6). The sink
// stores everything the connector uploads here, and media.get stores what it
// fetches on demand. The cache holds at most capBytes; the least recently
// touched files are evicted first. Bytes leave the bridge only through the
// link's media.get answers, never from Meta's CDN by a device.
package media

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultCap is the cache size: 500 MiB.
const DefaultCap = 500 << 20

// ErrTooLarge: the item exceeds the per-item limit; nothing was stored.
var ErrTooLarge = errors.New("media_too_large")

// ErrNotFound: no such item (never stored, or evicted).
var ErrNotFound = errors.New("media_not_found")

type entry struct {
	size    int64
	touched int64 // unix nano, LRU key
}

// Cache is a directory-backed, size-capped media store.
type Cache struct {
	dir string
	cap int64

	mu    sync.Mutex
	files map[string]entry
	total int64
}

// Open scans dir, drops partial writes and rebuilds the index.
func Open(dir string, capBytes int64) (*Cache, error) {
	if capBytes <= 0 {
		capBytes = DefaultCap
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	c := &Cache{dir: dir, cap: capBytes, files: map[string]entry{}}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, ent := range ents {
		if strings.HasPrefix(ent.Name(), ".part-") {
			os.Remove(filepath.Join(dir, ent.Name()))
			continue
		}
		info, err := ent.Info()
		if err != nil || !info.Mode().IsRegular() || !SafeID(ent.Name()) {
			continue
		}
		c.files[ent.Name()] = entry{size: info.Size(), touched: info.ModTime().UnixNano()}
		c.total += info.Size()
	}
	c.evictLocked("")
	return c, nil
}

// Put stores data and returns its content-addressed id.
func (c *Cache) Put(data []byte) (string, error) {
	id, _, err := c.PutReader(bytes.NewReader(data), -1)
	return id, err
}

// PutReader streams r into the cache under its content hash, reading at most
// max bytes (max < 0: no per-item limit). It never holds the item in memory.
func (c *Cache) PutReader(r io.Reader, max int64) (string, int64, error) {
	return c.put("", r, max)
}

// PutReaderAs streams r into the cache under a caller-chosen id.
func (c *Cache) PutReaderAs(id string, r io.Reader, max int64) (int64, error) {
	if !SafeID(id) {
		return 0, fmt.Errorf("bad media id")
	}
	_, n, err := c.put(id, r, max)
	return n, err
}

// CreatePart returns an empty partial file in the cache directory for a
// writer that needs an *os.File; Commit or Abort it.
func (c *Cache) CreatePart() (*os.File, error) {
	return os.CreateTemp(c.dir, ".part-*")
}

// Abort removes a partial file.
func (c *Cache) Abort(f *os.File) {
	f.Close()
	os.Remove(f.Name())
}

// Commit moves a partial file into the cache under id. Files over max bytes
// are refused (max < 0: no per-item limit).
func (c *Cache) Commit(f *os.File, id string, max int64) (int64, error) {
	defer c.Abort(f)
	if !SafeID(id) {
		return 0, fmt.Errorf("bad media id")
	}
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if max >= 0 && info.Size() > max {
		return 0, ErrTooLarge
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	return info.Size(), c.adopt(f.Name(), id, info.Size())
}

func (c *Cache) put(id string, r io.Reader, max int64) (string, int64, error) {
	f, err := c.CreatePart()
	if err != nil {
		return "", 0, err
	}
	defer c.Abort(f)
	var h hash.Hash = sha256.New()
	src := r
	if max >= 0 {
		src = io.LimitReader(r, max+1)
	}
	n, err := io.Copy(io.MultiWriter(f, h), src)
	if err != nil {
		return "", 0, err
	}
	if max >= 0 && n > max {
		return "", 0, ErrTooLarge
	}
	if id == "" {
		id = hex.EncodeToString(h.Sum(nil))[:32]
	}
	if err := f.Sync(); err != nil {
		return "", 0, err
	}
	return id, n, c.adopt(f.Name(), id, n)
}

func (c *Cache) adopt(path, id string, size int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.files[id]; ok {
		c.total -= old.size
	}
	if err := os.Rename(path, c.path(id)); err != nil {
		delete(c.files, id)
		return err
	}
	c.files[id] = entry{size: size, touched: time.Now().UnixNano()}
	c.total += size
	c.evictLocked(id)
	return nil
}

// Has reports whether id is cached and its size.
func (c *Cache) Has(id string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.files[id]
	return e.size, ok
}

// Get reads a whole item and touches it for LRU.
func (c *Cache) Get(id string) ([]byte, error) {
	if !SafeID(id) {
		return nil, fmt.Errorf("bad media id")
	}
	data, err := os.ReadFile(c.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	c.touch(id)
	return data, nil
}

// ReadAt reads at most n bytes of an item from offset and returns them with
// the item's total size.
func (c *Cache) ReadAt(id string, offset int64, n int) ([]byte, int64, error) {
	if !SafeID(id) {
		return nil, 0, fmt.Errorf("bad media id")
	}
	f, err := os.Open(c.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	} else if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if offset < 0 || offset > size {
		return nil, size, fmt.Errorf("offset out of range")
	}
	buf := make([]byte, min(int64(n), size-offset))
	if _, err := f.ReadAt(buf, offset); err != nil && !errors.Is(err, io.EOF) {
		return nil, size, err
	}
	c.touch(id)
	return buf, size, nil
}

func (c *Cache) touch(id string) {
	c.mu.Lock()
	if e, ok := c.files[id]; ok {
		e.touched = time.Now().UnixNano()
		c.files[id] = e
	}
	c.mu.Unlock()
}

// TotalBytes reports the current cache size.
func (c *Cache) TotalBytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

func (c *Cache) path(id string) string { return filepath.Join(c.dir, id) }

// evictLocked drops least-recently-touched files until under the cap, never
// the item just stored (keep).
func (c *Cache) evictLocked(keep string) {
	if c.total <= c.cap {
		return
	}
	ids := make([]string, 0, len(c.files))
	for id := range c.files {
		if id != keep {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(a, b int) bool { return c.files[ids[a]].touched < c.files[ids[b]].touched })
	for _, id := range ids {
		if c.total <= c.cap {
			break
		}
		e := c.files[id]
		if err := os.Remove(c.path(id)); err == nil || errors.Is(err, os.ErrNotExist) {
			c.total -= e.size
			delete(c.files, id)
		}
	}
}

// SafeID reports whether id is a cache id: 1 to 64 lowercase hex digits.
func SafeID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
