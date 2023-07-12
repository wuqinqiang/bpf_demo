package main

import (
	"fmt"
)

//go:noinline
func simpleFunction(val int) {
	fmt.Println("item value:", val)
}

func main() {
	simpleFunction(100)
}
