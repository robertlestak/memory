package memory

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type FileBackend struct {
	Dir string `json:"dir"`
}

func (b *FileBackend) Init(cfg any) error {
	jd, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(jd, b); err != nil {
		return err
	}
	if err := os.MkdirAll(b.Dir, 0700); err != nil {
		return err
	}
	return nil
}

func (b *FileBackend) Get(key string) ([]byte, error) {
	return os.ReadFile(filepath.Join(b.Dir, key))
}

func (b *FileBackend) Set(key string, value []byte) error {
	return os.WriteFile(filepath.Join(b.Dir, key), value, 0600)
}

func (b *FileBackend) Delete(key string) error {
	os.Remove(filepath.Join(b.Dir, key))
	return nil
}
