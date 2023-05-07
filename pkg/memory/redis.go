package memory

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/go-redis/redis/v7"
)

type RedisBackend struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Db       int    `json:"db"`
	TlsCa    string `json:"tls_ca"`
	TlsCert  string `json:"tls_cert"`
	TlsKey   string `json:"tls_key"`

	conn *redis.Client
}

func (m *RedisBackend) Init(cfg any) error {
	jd, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(jd, m); err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if m.TlsCa != "" {
		caCert, err := ioutil.ReadFile(m.TlsCa)
		if err != nil {
			return err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig = &tls.Config{
			RootCAs: caCertPool,
		}
	}
	if m.TlsCert != "" && m.TlsKey != "" {
		cert, err := tls.LoadX509KeyPair(m.TlsCert, m.TlsKey)
		if err != nil {
			return err
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	m.conn = redis.NewClient(&redis.Options{
		Addr:      fmt.Sprintf("%s:%d", m.Host, m.Port),
		Password:  m.Password,
		DB:        m.Db,
		TLSConfig: tlsConfig,
	})
	_, err = m.conn.Ping().Result()
	if err != nil {
		return err
	}
	return nil
}

func (m *RedisBackend) Get(key string) ([]byte, error) {
	val, err := m.conn.Get(key).Result()
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

func (m *RedisBackend) Set(key string, value []byte) error {
	return m.conn.Set(key, value, 0).Err()
}

func (m *RedisBackend) Delete(key string) error {
	return m.conn.Del(key).Err()
}
