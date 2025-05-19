package domainrouter

import "sync"

// ThreadMap for disallowing change of elements during runtime, for threadsafty
type ThreadMap[K comparable, V any] struct {
	dirty   map[K]V
	rwMutex sync.RWMutex
}

func NewThreadMap[K comparable, V any](m map[K]V) *ThreadMap[K, V] {
	return &ThreadMap[K, V]{
		dirty:   m,
		rwMutex: sync.RWMutex{},
	}
}

func (m *ThreadMap[K, V]) Get(key K) (value V, ok bool) {
	m.rwMutex.RLock()
	defer m.rwMutex.RUnlock()
	value, ok = m.dirty[key]
	return value, ok
}

func (m *ThreadMap[K, V]) SetValue(key K, change func(old V) V) bool {
	m.rwMutex.Lock()
	defer m.rwMutex.Unlock()

	value, ok := m.dirty[key]
	if !ok {
		return ok
	}

	m.dirty[key] = change(value)
	return ok
}
