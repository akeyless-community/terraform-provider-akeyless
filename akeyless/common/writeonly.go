package common

import (
	"context"

	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// rawConfigString returns a string attribute from the raw configuration.
// Write-only values are never stored in state or plan, so d.Get cannot read
// them. On refresh/import the raw config is null and this returns false.
func rawConfigString(d *schema.ResourceData, field string) (string, bool) {
	raw, diags := d.GetRawConfigAt(cty.GetAttrPath(field))
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

// ValidateWriteOnlyAttribute rejects configs that set both the legacy and the
// write-only attribute. Legacy-only configs are unchanged (no warning).
func ValidateWriteOnlyAttribute(oldField, woField cty.Path) schema.ValidateRawResourceConfigFunc {
	return func(ctx context.Context, req schema.ValidateResourceConfigFuncRequest, resp *schema.ValidateResourceConfigFuncResponse) {
		oldValue, oldErr := oldField.Apply(req.RawConfig)
		woValue, woErr := woField.Apply(req.RawConfig)
		if oldErr == nil && woErr == nil && !oldValue.IsNull() && !woValue.IsNull() {
			resp.Diagnostics = diag.Diagnostics{{
				Severity:      diag.Error,
				Summary:       "Conflicting configuration arguments",
				Detail:        "Use either the legacy or write-only secret attribute, not both.",
				AttributePath: woField,
			}}
		}
	}
}

// EffectiveSecretValue returns the write-only value when it is configured,
// otherwise the legacy value. Use it in Create, and in Update when the API
// replaces the stored secret with whatever is sent.
func EffectiveSecretValue(d *schema.ResourceData, field, woField string) string {
	if v, ok := rawConfigString(d, woField); ok {
		return v
	}
	return d.Get(field).(string)
}

// SecretValueForUpdate is for update APIs that keep the stored secret when it
// is omitted (rotated secrets). It returns nil, meaning "omit the secret",
// when the write-only path is in use and *_wo_version did not change, so a
// rotated value is not overwritten with a stale one from the config.
func SecretValueForUpdate(d *schema.ResourceData, field, woField string) (*string, error) {
	versionField := woField + "_version"
	if value, ok := rawConfigString(d, woField); ok {
		if !d.HasChange(versionField) {
			return nil, nil
		}
		if err := d.Set(field, nil); err != nil {
			return nil, err
		}
		return &value, nil
	}

	if UsingWriteOnly(d, woField, versionField) || writeOnlyVersionWasRemoved(d, versionField) {
		if value, ok := rawConfigString(d, field); ok {
			return &value, nil
		}
		return nil, nil
	}

	value := d.Get(field).(string)
	return &value, nil
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
	if _, ok := rawConfigString(d, woField); ok {
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
		return d.Set(field, nil)
	}
	return d.Set(field, value)
}
