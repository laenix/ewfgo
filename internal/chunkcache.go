package internal

import (
	"container/list"
	"sync"
)

// chunkCacheMaxBytes bounds the memory a decompressed-chunk cache may hold.
// The cache speeds up random-access reads (a forensic engine or NBD client
// that revisits the same 32 KiB chunk across calls); the strictly sequential
// path reads each chunk once and gains nothing from it.
const chunkCacheMaxBytes = 64 << 20 // 64 MiB of decompressed chunk data

type chunkKey struct {
	si int // section index
	ci int // chunk index within the section
}

type chunkCacheEntry struct {
	key  chunkKey
	data []byte
}

// chunkCache is a byte-bounded LRU of decompressed chunks. Decompressed chunk
// data is immutable for the lifetime of a read-only image, so an entry is
// never invalidated — eviction is pure capacity management and callers may
// hold the returned slice safely (readChunkForSection never mutates it).
type chunkCache struct {
	mu    sync.Mutex
	cap   int
	size  int
	items map[chunkKey]*list.Element
	lru   *list.List // front = most recently used
}

func newChunkCache(cap int) *chunkCache {
	return &chunkCache{
		cap:   cap,
		items: make(map[chunkKey]*list.Element),
		lru:   list.New(),
	}
}

func (c *chunkCache) get(si, ci int) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[chunkKey{si, ci}]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*chunkCacheEntry).data, true
	}
	return nil, false
}

func (c *chunkCache) put(si, ci int, data []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := chunkKey{si, ci}
	if el, ok := c.items[key]; ok {
		c.lru.MoveToFront(el)
		ent := el.Value.(*chunkCacheEntry)
		c.size += len(data) - len(ent.data)
		ent.data = data
	} else {
		c.items[key] = c.lru.PushFront(&chunkCacheEntry{key: key, data: data})
		c.size += len(data)
	}
	// Evict from the back (least recently used) until under the byte cap.
	for c.size > c.cap && c.lru.Len() > 0 {
		back := c.lru.Back()
		ent := back.Value.(*chunkCacheEntry)
		c.lru.Remove(back)
		delete(c.items, ent.key)
		c.size -= len(ent.data)
	}
}
