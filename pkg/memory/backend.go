package memory

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/robertlestak/memory/pkg/keys"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	B   Backend
	Key *rsa.PrivateKey
)

type BackendType string

const (
	MemoryBackendType  BackendType = "memory"
	MemoryBackendRedis BackendType = "redis"
	MemoryBackendFile  BackendType = "file"
)

var (
	locks map[string]*sync.Mutex
)

type Backend interface {
	Init(cfg any) error
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
}

func New(t BackendType, cfg any, key *rsa.PrivateKey) error {
	switch t {
	case MemoryBackendType:
		B = &MemoryBackend{}
	case MemoryBackendRedis:
		B = &RedisBackend{}
	case MemoryBackendFile:
		B = &FileBackend{}
	default:
		return fmt.Errorf("unknown backend type: %s", t)
	}
	Key = key
	if err := Init(cfg); err != nil {
		return err
	}
	locks = make(map[string]*sync.Mutex)
	return nil
}

func lockKey(key string) {
	if _, ok := locks[key]; !ok {
		locks[key] = &sync.Mutex{}
	}
	locks[key].Lock()
}

func unlockKey(key string) {
	if _, ok := locks[key]; !ok {
		locks[key] = &sync.Mutex{}
	}
	locks[key].Unlock()
}

func Get(key string, obj any) error {
	lockKey(key)
	defer unlockKey(key)
	v, err := B.Get(key)
	if err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	if Key != nil {
		v, err = keys.Decrypt(v, Key)
		if err != nil {
			return err
		}
	}
	return Unmarshal(v, obj)
}

func Set(key string, value any) error {
	lockKey(key)
	defer unlockKey(key)
	v, err := Marshal(value)
	if err != nil {
		return err
	}
	if Key != nil {
		v, err = keys.Encrypt(v, &Key.PublicKey)
		if err != nil {
			return err
		}
	}
	return B.Set(key, v)
}

func Delete(key string) error {
	lockKey(key)
	defer unlockKey(key)
	return B.Delete(key)
}

func Init(cfg any) error {
	return B.Init(cfg)
}

func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

func KeyFromTTY() (*rsa.PrivateKey, error) {
	fmt.Println("Enter private key:")
	state, err := terminal.MakeRaw(0)
	if err != nil {
		return nil, err
	}
	term := terminal.NewTerminal(os.Stdout, "")
	// capture ctrl+c, ctrl+d, etc so we can exit
	term.AutoCompleteCallback = func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
		if key == 3 || key == 4 || key == 13 {
			terminal.Restore(0, state)
			os.Exit(0)
		}
		return "", 0, false
	}
	var key []byte
	for {
		k, err := term.ReadPassword("")
		if err != nil {
			return nil, err
		}
		// delete line in terminal so we don't have a blank line
		term.Write([]byte("\033[1A\033[2K"))
		if len(k) > 0 {
			kline := fmt.Sprintf("%s\n", k)
			key = append(key, []byte(kline)...)
			// if line contains END, then we're done
			if strings.Contains(kline, "END") {
				break
			}
		}
		if len(k) == 0 {
			break
		}
	}

	terminal.Restore(0, state)
	priv, err := keys.ByesToPrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func KeyFromEnv() (*rsa.PrivateKey, error) {
	key := os.Getenv("MEMORY_KEY")
	if key == "" {
		return nil, fmt.Errorf("MEMORY_KEY environment variable not set")
	}
	priv, err := keys.ByesToPrivateKey([]byte(key))
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// ReadKey will read a private key, parse it, and return a *rsa.PrivateKey
// If path is provided, the key will be read from the file at that path
// If a MEMORY_KEY environment variable is set, the key will be read from that
// If path is nil and MEMORY_KEY is not set, the user will be prompted to enter a key
// If remove is true, the file at path will be removed after reading
func ReadKey(path *string, remove bool) (*rsa.PrivateKey, error) {
	if path == nil || *path == "" {
		if os.Getenv("MEMORY_KEY") != "" {
			return KeyFromEnv()
		}
		return KeyFromTTY()
	}
	fd, err := os.ReadFile(*path)
	if err != nil {
		return nil, err
	}
	k, err := keys.ByesToPrivateKey(fd)
	if err != nil {
		return nil, err
	}
	if remove {
		if path != nil {
			if err := os.Remove(*path); err != nil {
				return nil, err
			}
		}
	}
	return k, nil
}
