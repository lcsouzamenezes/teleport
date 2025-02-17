/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package backend

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/gravitational/teleport/api/types"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

// TestBufferSizes tests various combinations of various
// buffer sizes and lists
func TestBufferSizes(t *testing.T) {
	list(t, 1, 100)
	list(t, 2, 100)
	list(t, 3, 100)
	list(t, 4, 100)
}

// TestBufferSizesReset tests various combinations of various
// buffer sizes and lists with clear.
func TestBufferSizesReset(t *testing.T) {
	b := NewCircularBuffer(
		BufferCapacity(1),
	)
	defer b.Close()
	b.SetInit()

	listWithBuffer(t, b, 1, 100)
	b.Clear()
	listWithBuffer(t, b, 1, 100)
}

// TestWatcherSimple tests scenarios with watchers
func TestWatcherSimple(t *testing.T) {
	ctx := context.Background()
	b := NewCircularBuffer(
		BufferCapacity(3),
	)
	defer b.Close()
	b.SetInit()

	w, err := b.NewWatcher(ctx, Watch{})
	require.NoError(t, err)
	defer w.Close()

	select {
	case e := <-w.Events():
		require.Equal(t, e.Type, types.OpInit)
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: 1}})

	select {
	case e := <-w.Events():
		require.Equal(t, e.Item.ID, int64(1))
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	b.Close()
	b.Emit(Event{Item: Item{ID: 2}})

	select {
	case <-w.Done():
		// expected
	case <-w.Events():
		t.Fatalf("unexpected event")
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}
}

// TestWatcherCapacity checks various watcher capacity scenarios
func TestWatcherCapacity(t *testing.T) {
	const gracePeriod = time.Second
	clock := clockwork.NewFakeClock()

	ctx := context.Background()
	b := NewCircularBuffer(
		BufferCapacity(1),
		BufferClock(clock),
		BacklogGracePeriod(gracePeriod),
	)
	defer b.Close()
	b.SetInit()

	w, err := b.NewWatcher(ctx, Watch{
		QueueSize: 1,
	})
	require.NoError(t, err)
	defer w.Close()

	select {
	case e := <-w.Events():
		require.Equal(t, e.Type, types.OpInit)
	default:
		t.Fatalf("Expected immediate OpInit.")
	}

	// emit and then consume 10 events.  this is much larger than our queue size,
	// but should succeed since we consume within our grace period.
	for i := 0; i < 10; i++ {
		b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: int64(i + 1)}})
	}
	for i := 0; i < 10; i++ {
		select {
		case e := <-w.Events():
			require.Equal(t, e.Item.ID, int64(i+1))
		default:
			t.Fatalf("Expected events to be immediately available")
		}
	}

	// advance further than grace period.
	clock.Advance(gracePeriod + time.Second)

	// emit another event, which will cause buffer to reevaluate the grace period.
	b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: int64(11)}})

	// ensure that buffer did not close watcher, since previously created backlog
	// was drained within grace period.
	select {
	case <-w.Done():
		t.Fatalf("Watcher should not have backlog, but was closed anyway")
	default:
	}

	// create backlog again, and this time advance past grace period without draining it.
	for i := 0; i < 10; i++ {
		b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: int64(i + 12)}})
	}
	clock.Advance(gracePeriod + time.Second)

	// emit another event, which will cause buffer to realize that watcher is past
	// its grace period.
	b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: int64(22)}})

	select {
	case <-w.Done():
	default:
		t.Fatalf("buffer did not close watcher that was past grace period")
	}
}

// TestWatcherClose makes sure that closed watcher
// will be removed
func TestWatcherClose(t *testing.T) {
	b := NewCircularBuffer(
		BufferCapacity(3),
	)
	defer b.Close()
	b.SetInit()

	w, err := b.NewWatcher(context.TODO(), Watch{})
	require.NoError(t, err)

	select {
	case e := <-w.Events():
		require.Equal(t, e.Type, types.OpInit)
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	require.Equal(t, b.watchers.Len(), 1)
	w.(*BufferWatcher).closeAndRemove(removeSync)
	require.Equal(t, b.watchers.Len(), 0)
}

// TestRemoveRedundantPrefixes removes redundant prefixes
func TestRemoveRedundantPrefixes(t *testing.T) {
	type tc struct {
		in  [][]byte
		out [][]byte
	}
	tcs := []tc{
		{
			in:  [][]byte{},
			out: [][]byte{},
		},
		{
			in:  [][]byte{[]byte("/a")},
			out: [][]byte{[]byte("/a")},
		},
		{
			in:  [][]byte{[]byte("/a"), []byte("/")},
			out: [][]byte{[]byte("/")},
		},
		{
			in:  [][]byte{[]byte("/b"), []byte("/a")},
			out: [][]byte{[]byte("/a"), []byte("/b")},
		},
		{
			in:  [][]byte{[]byte("/a/b"), []byte("/a"), []byte("/a/b/c"), []byte("/d")},
			out: [][]byte{[]byte("/a"), []byte("/d")},
		},
	}
	for _, tc := range tcs {
		require.Empty(t, cmp.Diff(removeRedundantPrefixes(tc.in), tc.out))
	}
}

// TestWatcherMulti makes sure that watcher
// with multiple matching prefixes will get an event only once
func TestWatcherMulti(t *testing.T) {
	b := NewCircularBuffer(
		BufferCapacity(3),
	)
	defer b.Close()
	b.SetInit()

	w, err := b.NewWatcher(context.TODO(), Watch{Prefixes: [][]byte{[]byte("/a"), []byte("/a/b")}})
	require.NoError(t, err)
	defer w.Close()

	select {
	case e := <-w.Events():
		require.Equal(t, e.Type, types.OpInit)
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	b.Emit(Event{Item: Item{Key: []byte("/a/b/c"), ID: 1}})

	select {
	case e := <-w.Events():
		require.Equal(t, e.Item.ID, int64(1))
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	require.Equal(t, len(w.Events()), 0)

}

// TestWatcherReset tests scenarios with watchers and buffer resets
func TestWatcherReset(t *testing.T) {
	b := NewCircularBuffer(
		BufferCapacity(3),
	)
	defer b.Close()
	b.SetInit()

	w, err := b.NewWatcher(context.TODO(), Watch{})
	require.NoError(t, err)
	defer w.Close()

	select {
	case e := <-w.Events():
		require.Equal(t, e.Type, types.OpInit)
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: 1}})
	b.Clear()

	// make sure watcher has been closed
	select {
	case <-w.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for close event.")
	}

	w2, err := b.NewWatcher(context.TODO(), Watch{})
	require.NoError(t, err)
	defer w2.Close()

	select {
	case e := <-w2.Events():
		require.Equal(t, e.Type, types.OpInit)
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}

	b.Emit(Event{Item: Item{Key: []byte{Separator}, ID: 2}})

	select {
	case e := <-w2.Events():
		require.Equal(t, e.Item.ID, int64(2))
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Timeout waiting for event.")
	}
}

// TestWatcherTree tests buffer watcher tree
func TestWatcherTree(t *testing.T) {
	wt := newWatcherTree()
	require.Equal(t, wt.rm(nil), false)

	w1 := &BufferWatcher{Watch: Watch{Prefixes: [][]byte{[]byte("/a"), []byte("/a/a1"), []byte("/c")}}}
	require.Equal(t, wt.rm(w1), false)

	w2 := &BufferWatcher{Watch: Watch{Prefixes: [][]byte{[]byte("/a")}}}

	wt.add(w1)
	wt.add(w2)

	var out []*BufferWatcher
	wt.walk(func(w *BufferWatcher) {
		out = append(out, w)
	})
	require.Len(t, out, 4)

	var matched []*BufferWatcher
	wt.walkPath("/c", func(w *BufferWatcher) {
		matched = append(matched, w)
	})
	require.Len(t, matched, 1)
	require.Equal(t, matched[0], w1)

	matched = nil
	wt.walkPath("/a", func(w *BufferWatcher) {
		matched = append(matched, w)
	})
	require.Len(t, matched, 2)
	require.Equal(t, matched[0], w1)
	require.Equal(t, matched[1], w2)

	require.Equal(t, wt.rm(w1), true)
	require.Equal(t, wt.rm(w1), false)

	matched = nil
	wt.walkPath("/a", func(w *BufferWatcher) {
		matched = append(matched, w)
	})
	require.Len(t, matched, 1)
	require.Equal(t, matched[0], w2)

	require.Equal(t, wt.rm(w2), true)
}

func makeIDs(size int) []int64 {
	out := make([]int64, size)
	for i := 0; i < size; i++ {
		out[i] = int64(i)
	}
	return out
}

func expectEvents(t *testing.T, b *CircularBuffer, ids []int64) {
	events := b.Events()
	if len(ids) == 0 {
		require.Equal(t, len(events), 0)
		return
	}
	require.Empty(t, cmp.Diff(toIDs(events), ids))
}

func toIDs(e []Event) []int64 {
	var out []int64
	for i := 0; i < len(e); i++ {
		out = append(out, e[i].Item.ID)
	}
	return out
}

func list(t *testing.T, bufferSize int, listSize int) {
	b := NewCircularBuffer(
		BufferCapacity(bufferSize),
	)
	defer b.Close()
	b.SetInit()
	listWithBuffer(t, b, bufferSize, listSize)
}

func listWithBuffer(t *testing.T, b *CircularBuffer, bufferSize int, listSize int) {
	// empty by default
	expectEvents(t, b, nil)

	elements := makeIDs(listSize)

	// push through all elements of the list and make sure
	// the slice always matches
	for i := 0; i < len(elements); i++ {
		b.Emit(Event{Item: Item{ID: elements[i]}})
		sliceEnd := i + 1 - bufferSize
		if sliceEnd < 0 {
			sliceEnd = 0
		}
		expectEvents(t, b, elements[sliceEnd:i+1])
	}
}
