package common

import (
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// writeOnlyRaw returns the configured write-only value when raw config is
// available and the attribute is set. On refresh/import, older Terraform, or
// legacy configs, GetRawConfigAt may return diagnostics or a null value —
// callers should treat that as "WO not present" and fall back.
func writeOnlyRaw(d *schema.ResourceData, woField string) (string, bool) {
	raw, diags := d.GetRawConfigAt(cty.GetAttrPath(woField))
	if diags.HasError() || raw.IsNull() {
		return "", false
	}
	return raw.AsString(), true
}

// EffectiveSecretValue resolves a sensitive field that has both a regular
// (state-persisted) variant and a write-only variant (e.g. "mysql_password"
// and "mysql_password_wo"). The write-only value takes precedence when set,
// since it is the one Terraform 1.11+ practitioners are expected to use.
//
// Write-only values never appear in state or plan, so they must be read from
// the raw configuration via GetRawConfigAt rather than d.Get().
func EffectiveSecretValue(d *schema.ResourceData, field, woField string) (string, error) {
	if v, ok := writeOnlyRaw(d, woField); ok {
		return v, nil
	}
	return d.Get(field).(string), nil
}

// UsingWriteOnly reports whether the practitioner opted into the write-only
// path for a secret field. True when *_wo is present in raw config, or when
// *_wo_version is non-zero in state (the version survives refresh; the WO
// value itself never does).
func UsingWriteOnly(d *schema.ResourceData, woField, woVersionField string) bool {
	if _, ok := writeOnlyRaw(d, woField); ok {
		return true
	}
	v, ok := d.Get(woVersionField).(int)
	return ok && v != 0
}

// SetSecretFromRead sets a secret attribute from a Read API response.
// When the write-only path is in use, the attribute is cleared in state
// instead of persisting the secret. Existing non-WO configs keep the old
// behavior (value is written to state).
func SetSecretFromRead(d *schema.ResourceData, field, woField, woVersionField, value string) error {
	if UsingWriteOnly(d, woField, woVersionField) {
		return d.Set(field, "")
	}
	return d.Set(field, value)
}
