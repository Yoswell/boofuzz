package utils

import "fmt"

type Headers []string

func (h *Headers) String() string {
    return fmt.Sprintf("%v", *h)
}

func (h *Headers) Set(value string) error {
    *h = append(*h, value)
    return nil
}