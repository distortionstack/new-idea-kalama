package main

import (
	"testing"
	"time"
)

func TestRejectsMalformedAndUnversionedPURLWithoutNetwork(t *testing.T) {
	for _, input := range []string{"not-a-purl", "pkg:npm/lodash"} {
		got := resolve(time.Second, []string{input})
		if got.Status != "PROVIDER_ERROR" || len(got.Errors) != 1 || got.Errors[0].Kind != "MALFORMED" {
			t.Fatalf("resolve(%q) = %#v", input, got)
		}
	}
}

func TestRequiresExactlyOnePURL(t *testing.T) {
	got := resolve(time.Second, nil)
	if got.Status != "PROVIDER_ERROR" || got.Errors[0].Kind != "MALFORMED" {
		t.Fatalf("resolve() = %#v", got)
	}
}
