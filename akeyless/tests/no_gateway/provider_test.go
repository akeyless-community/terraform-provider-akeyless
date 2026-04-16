package no_gateway

import (
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
)

func TestProvider(t *testing.T) {
	if err := akeyless.Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}
