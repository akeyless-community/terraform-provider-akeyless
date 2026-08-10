package common

import (
	"fmt"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// writeOnlyRaw returns the configured write-only value when raw config is
// available and the attribute is set. On refresh/import, older Terraform, or
// legacy configs, GetRawConfigAt may return diagnostics or a null value —
// callers should treat that as "WO not present" and fall back.
func writeOnlyRaw(d *schema.ResourceData, woField string) (string, bool) {
	raw, diags := d.GetRawConfigAt(cty.GetAttrPath(woField))
	if diags.HasError() {
		return "", false
	}
	return rawString(raw)
}

func rawString(raw cty.Value) (string, bool) {
	if raw.IsNull() || !raw.IsKnown() || raw.Type() != cty.String {
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

// SecretValueForUpdate returns nil when a write-only value was previously used
// but is unavailable in the current configuration. Callers must then omit the
// secret from the update request to avoid replacing it with an empty string.
func SecretValueForUpdate(d *schema.ResourceData, field, woField string) (*string, error) {
	if value, ok := writeOnlyRaw(d, woField); ok {
		return &value, nil
	}

	versionField := woField + "_version"
	if UsingWriteOnly(d, woField, versionField) || writeOnlyVersionWasRemoved(d, versionField) {
		return nil, nil
	}

	value := d.Get(field).(string)
	return &value, nil
}

// RequiredSecretValueForUpdate returns an error rather than sending an empty
// secret when an API request cannot omit its secret field.
func RequiredSecretValueForUpdate(d *schema.ResourceData, field, woField string) (string, error) {
	value, err := SecretValueForUpdate(d, field, woField)
	if err != nil {
		return "", err
	}
	if value == nil {
		return "", fmt.Errorf("%s must be set when updating a write-only secret", woField)
	}
	return *value, nil
}

func writeOnlyVersionWasRemoved(d *schema.ResourceData, versionField string) bool {
	old, current := d.GetChange(versionField)
	oldVersion, oldOK := old.(int)
	currentVersion, currentOK := current.(int)
	return oldOK && currentOK && oldVersion != 0 && currentVersion == 0
}

// SetOptionalString sets string and *string API request fields when available.
func SetOptionalString(destination interface{}, value *string) {
	if value == nil {
		return
	}
	switch destination := destination.(type) {
	case *string:
		*destination = *value
	case **string:
		*destination = value
	}
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
