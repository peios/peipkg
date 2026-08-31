package compose

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// parallelMap fills out[i] = fn(i) for i in [0, n), running fn on up to
// workers goroutines (capped at n; GOMAXPROCS when workers < 1). The
// output order is the input order, so a caller's determinism is
// untouched by the scheduling. On error the remaining work is skipped
// and the error at the lowest index seen wins, so repeated failing runs
// report the same failure.
func parallelMap[T any](n, workers int, fn func(i int) (T, error)) ([]T, error) {
	out := make([]T, n)
	if workers < 1 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > n {
		workers = n
	}
	var (
		next   atomic.Int64
		wg     sync.WaitGroup
		mu     sync.Mutex
		errIdx = n
		first  error
	)
	next.Store(-1)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1))
				if i >= n {
					return
				}
				mu.Lock()
				failed := first != nil
				mu.Unlock()
				if failed {
					return
				}
				v, err := fn(i)
				if err != nil {
					mu.Lock()
					if i < errIdx {
						errIdx, first = i, err
					}
					mu.Unlock()
					return
				}
				out[i] = v
			}
		}()
	}
	wg.Wait()
	if first != nil {
		return nil, first
	}
	return out, nil
}
