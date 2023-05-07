package main

import (
	"log"

	"github.com/robertlestak/memory/pkg/memory"
)

type example struct {
	Foo      string
	Bar      string
	SomeMore map[string]string
}

func (e *example) Get() error {
	return memory.Get("example.foo:"+e.Foo, e)
}

func (e *example) Set() error {
	return memory.Set("example.foo:"+e.Foo, e)
}

func main() {
	key, err := memory.ReadKey(nil, true)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &memory.RedisBackend{
		Host: "localhost",
		Port: 6379,
	}
	if err := memory.New(memory.MemoryBackendRedis, cfg, key); err != nil {
		log.Fatal(err)
	}
	test := example{
		Foo: "bar",
		Bar: "baz",
		SomeMore: map[string]string{
			"foo": "bar",
			"bar": "baz",
		},
	}
	if err := test.Set(); err != nil {
		log.Fatal(err)
	}
	returned := example{
		Foo: "bar",
	}
	if err := returned.Get(); err != nil {
		log.Fatal(err)
	}
	log.Printf("returned: %v", returned)
}
