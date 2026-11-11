package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"maunium.net/go/mautrix/mediaproxy"

	"github.com/tzarebczan/eggomi-meta-bridge/link"
	"github.com/tzarebczan/eggomi-meta-bridge/media"
	"github.com/tzarebczan/eggomi-meta-bridge/sink"
)

// directCacheID names a direct media ref's bytes in the cache, so later
// chunks of the same ref are served without fetching again.
func directCacheID(ref string) string {
	sum := sha256.Sum256([]byte("direct:" + ref))
	return hex.EncodeToString(sum[:16])
}

// mediaGet returns one chunk of a media item (PROTOCOL.md section 6). Direct refs are
// fetched through the connector (and so through the egress) on first use,
// streamed to the cache, and served from there.
func (c *Core) mediaGet(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Ref    string `json:"ref"`
		Offset int64  `json:"offset"`
	}
	if err := decode(params, &p); err != nil {
		return nil, err
	}
	if len(p.Ref) < 2 || len(p.Ref) > 2048 || p.Offset < 0 {
		return nil, errBadRequest
	}
	var id string
	switch p.Ref[0] {
	case sink.RefCached:
		id = p.Ref[1:]
		if !media.SafeID(id) {
			return nil, errBadRequest
		}
	case sink.RefDirect:
		mediaID, ok := sink.DirectMediaID(p.Ref)
		if !ok {
			return nil, errBadRequest
		}
		id = directCacheID(p.Ref)
		if err := c.fetchDirect(ctx, id, mediaID); err != nil {
			return nil, err
		}
	default:
		return nil, errBadRequest
	}
	chunk, size, err := c.o.Media.ReadAt(id, p.Offset, ChunkBytes)
	if errors.Is(err, media.ErrNotFound) {
		return nil, link.Code("media_not_found")
	} else if err != nil {
		if size > 0 && p.Offset > size {
			return nil, errBadRequest
		}
		return nil, err
	}
	return map[string]any{
		"ref":    p.Ref,
		"size":   size,
		"offset": p.Offset,
		"data":   base64.StdEncoding.EncodeToString(chunk),
	}, nil
}

// fetchDirect makes sure a direct ref's bytes are cached. One fetch runs at
// a time; a waiting request finds the bytes cached when it gets the lock.
func (c *Core) fetchDirect(ctx context.Context, id string, mediaID []byte) error {
	if _, ok := c.o.Media.Has(id); ok {
		return nil
	}
	c.mediaMu.Lock()
	defer c.mediaMu.Unlock()
	if _, ok := c.o.Media.Has(id); ok {
		return nil
	}
	if c.o.Download == nil {
		return link.Code("media_unavailable")
	}
	dctx, cancel := context.WithTimeout(ctx, MediaTimeout)
	defer cancel()
	dctx = c.o.Log.With().Str("component", "media").Logger().WithContext(dctx)
	resp, err := c.o.Download(dctx, mediaID, nil)
	if err != nil {
		c.o.Log.Debug().Err(err).Msg("direct media fetch failed")
		return link.Code("media_unavailable")
	}
	max := c.o.MaxMedia
	switch r := resp.(type) {
	case *mediaproxy.GetMediaResponseData:
		defer r.Reader.Close()
		if r.ContentLength > max {
			return link.Code("media_too_large")
		}
		_, err = c.o.Media.PutReaderAs(id, r.Reader, max)
	case *mediaproxy.GetMediaResponseFile:
		var f *os.File
		if f, err = c.o.Media.CreatePart(); err != nil {
			return err
		}
		var meta *mediaproxy.FileMeta
		if meta, err = r.Callback(f); err != nil {
			c.o.Media.Abort(f)
			c.o.Log.Debug().Err(err).Msg("direct media fetch failed")
			return link.Code("media_unavailable")
		}
		if meta != nil && meta.ReplacementFile != "" {
			c.o.Media.Abort(f)
			defer os.Remove(meta.ReplacementFile)
			repl, oerr := os.Open(meta.ReplacementFile)
			if oerr != nil {
				return oerr
			}
			defer repl.Close()
			_, err = c.o.Media.PutReaderAs(id, repl, max)
		} else {
			_, err = c.o.Media.Commit(f, id, max)
		}
	default:
		return link.Code("media_unavailable")
	}
	if errors.Is(err, media.ErrTooLarge) {
		return link.Code("media_too_large")
	}
	return err
}
