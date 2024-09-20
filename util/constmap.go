package util

// ImmutableMap for disallowing change of elements during runtime, for threadsafty
type ImmutableMap[K comparable, V any] struct {
	dirty map[K]V
}

func NewImmutableMap[K comparable, V any](m map[K]V) *ImmutableMap[K, V] {
	return &ImmutableMap[K, V]{
		dirty: m,
	}
}

func (m *ImmutableMap[K, V]) Get(key K) (value V, ok bool) {
	value, ok = m.dirty[key]
	return value, ok
}
