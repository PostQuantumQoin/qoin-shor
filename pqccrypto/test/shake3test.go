package main

import (
	// "bytes"
	// "io"
	"fmt"

	"pqccrypto/shake3"
)

func main() {
	msg := []byte("hello")
	sh := shake3.Shake256XOF(msg, 72)
	fmt.Printf("sh3:%x\n", sh)
	fmt.Println("sh3 len", sh, len(sh))
	// 2fb79e35e151035c7d4719d4e743d6db9d67bf41d8f868e7a7c505cc5514f029
	// 2fb79e35e151035c7d4719d4e743d6db9d67bf41d8f868e7a7c505cc5514f029

	// 1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f22162
	// 1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f22162

	// 1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f221626f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be38ce9f457bf32e6b2
	// 1234075ae4a1e77316cf2d8000974581a343b9ebbca7e3d1db83394c30f221626f594e4f0de63902349a5ea5781213215813919f92a4d86d127466e3d07e8be38ce9f457bf32e6b2
}
