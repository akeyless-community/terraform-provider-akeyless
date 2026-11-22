package common

import (
	"context"
	"encoding/base64"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// SecretValueForRotatedUpdate is like SecretValueForUpdate, but when the
// write-only path omits the secret (version unchanged) it loads the current
// value from the API so metadata-only updates do not clear rotated secret data.
func SecretValueForRotatedUpdate(
	ctx context.Context,
	client akeyless_api.V2ApiService,
	token string,
	name string,
	d *schema.ResourceData,
	field, woField, valueKey string,
) (*string, error) {
	return secretValueForRotatedUpdate(ctx, client, token, name, d, field, woField, valueKey, false)
}

// PrivateKeyForRotatedUpdate is SecretValueForRotatedUpdate for base64 private
// key fields (SSH key_data_base64, Snowflake private_key). The API returns the
// stored key as PEM, so a reloaded key is base64-encoded before it is sent back.
func PrivateKeyForRotatedUpdate(
	ctx context.Context,
	client akeyless_api.V2ApiService,
	token string,
	name string,
	d *schema.ResourceData,
	field, woField string,
) (*string, error) {
	return secretValueForRotatedUpdate(ctx, client, token, name, d, field, woField, "private_key", true)
}

func secretValueForRotatedUpdate(
	ctx context.Context,
	client akeyless_api.V2ApiService,
	token string,
	name string,
	d *schema.ResourceData,
	field, woField, valueKey string,
	encodeBase64 bool,
) (*string, error) {
	value, err := SecretValueForUpdate(d, field, woField)
	if err != nil {
		return nil, err
	}
	if value != nil {
		return value, nil
	}

	versionField := woField + "_version"
	if !UsingWriteOnly(d, woField, versionField) {
		return nil, nil
	}

	stored, err := rotatedSecretJSONValue(ctx, client, token, name, valueKey)
	if err != nil {
		return nil, err
	}
	if stored == "" {
		return nil, nil
	}
	if encodeBase64 {
		stored = base64.StdEncoding.EncodeToString([]byte(stored))
	}
	return &stored, nil
}

func rotatedSecretJSONValue(ctx context.Context, client akeyless_api.V2ApiService, token, name, valueKey string) (string, error) {
	body := akeyless_api.RotatedSecretGetValue{
		Name:  name,
		Token: &token,
	}
	rOut, _, err := client.RotatedSecretGetValue(ctx).Body(body).Execute()
	if err != nil {
		return "", fmt.Errorf("can't get rotated secret value for %s: %w", name, err)
	}

	val, ok := rOut["value"]
	if !ok {
		return "", nil
	}
	value, ok := val.(map[string]any)
	if !ok {
		return "", nil
	}
	raw, ok := value[valueKey]
	if !ok {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("rotated secret %s: %q is not a string", name, valueKey)
	}
	return s, nil
}