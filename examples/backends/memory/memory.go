package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"

	"github.com/robertlestak/memory/pkg/memory"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	if err := memory.New(memory.MemoryBackendType, nil, key); err != nil {
		log.Fatal(err)
	}
	test := map[string]string{
		"foo": "bar",
		"bar": "baz",
	}
	if err := memory.Set("test", test); err != nil {
		log.Fatal(err)
	}
	var returned map[string]string
	err = memory.Get("test", &returned)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("returned: %v", returned)
}
