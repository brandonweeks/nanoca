package storagetest

import (
	"testing"

	"github.com/brandonweeks/nanoca"
)

func TestMemoryStorageConformance(t *testing.T) {
	t.Parallel()

	RunConformanceTests(t, func(*testing.T) nanoca.Storage {
		return nanoca.NewMemoryStorage()
	})
}
