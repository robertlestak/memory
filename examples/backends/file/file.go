package main

import (
	"log"

	"github.com/robertlestak/memory/pkg/memory"
)

func main() {
	var keyFile string
	// keyFile = os.Getenv("HOME") + "/.ssh/id_rsa"
	key, err := memory.ReadKey(&keyFile, true)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &memory.FileBackend{
		Dir: "/tmp/memory",
	}
	if err := memory.New(memory.MemoryBackendFile, cfg, key); err != nil {
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
