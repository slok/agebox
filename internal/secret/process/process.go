package process

import (
	"context"
	"sync"
)

// IDProcessor knows how to process Secret IDs.
// The processors could mutate or validate them.
type IDProcessor interface {
	ProcessID(ctx context.Context, secretID string) (string, error)
}

//go:generate mockery --case underscore --output processmock --outpkg processmock --name IDProcessor

// IDProcessorFunc is a helper type to create IDProcessors from functions.
type IDProcessorFunc func(ctx context.Context, secretID string) (string, error)

// ProcessID satisfies IDProcessor interface.
func (f IDProcessorFunc) ProcessID(ctx context.Context, secretID string) (string, error) {
	return f(ctx, secretID)
}

type noopIDProcessor bool

func (noopIDProcessor) ProcessID(_ context.Context, secretID string) (string, error) {
	return secretID, nil
}

// NoopIDProcessor is a noop ID secret processor.
const NoopIDProcessor = noopIDProcessor(false)

// NewIDProcessorChain returns a processor that chains multiple processors at the same time.
func NewIDProcessorChain(processors ...IDProcessor) IDProcessor {
	return IDProcessorFunc(func(ctx context.Context, secretID string) (string, error) {
		var err error
		for _, proc := range processors {
			secretID, err = proc.ProcessID(ctx, secretID)
			if err != nil {
				return "", err
			}

			// Just ignore if empty.
			if secretID == "" {
				return "", nil
			}
		}

		return secretID, nil
	})
}

// NewIgnoreAlreadyProcessed maintains an internal cache with the already processed, if
// already in cache it will ignore.
// Warning: If we want to reset the cache we need a new processor.
func NewIgnoreAlreadyProcessed(cache map[string]struct{}) IDProcessor {
	if cache == nil {
		cache = map[string]struct{}{}
	}

	var mu sync.Mutex

	return IDProcessorFunc(func(_ context.Context, secretID string) (string, error) {
		mu.Lock()
		defer mu.Unlock()

		// Check already processed.
		_, ok := cache[secretID]
		if ok {
			return "", nil
		}

		// Store as processed.
		cache[secretID] = struct{}{}

		return secretID, nil
	})
}
