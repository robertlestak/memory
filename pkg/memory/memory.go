package memory

type MemoryBackend struct {
	D map[string][]byte
}

func (m *MemoryBackend) Init(cfg any) error {
	m.D = make(map[string][]byte)
	return nil
}

func (m *MemoryBackend) Get(key string) ([]byte, error) {
	return m.D[key], nil
}

func (m *MemoryBackend) Set(key string, value []byte) error {
	m.D[key] = value
	return nil
}

func (m *MemoryBackend) Delete(key string) error {
	delete(m.D, key)
	return nil
}
