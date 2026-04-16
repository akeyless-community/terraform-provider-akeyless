package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
)

func getAccountSettings(m interface{}) (*akeyless_api.GetAccountSettingsCommandOutput, error) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	body := akeyless_api.GetAccountSettings{Token: &token}
	rOut, _, err := client.GetAccountSettings(context.Background()).Body(body).Execute()
	return rOut, err
}

func extractAccountJwtTtlDefault(rOutAcc *akeyless_api.GetAccountSettingsCommandOutput) int64 {
	if rOutAcc == nil || rOutAcc.SystemAccessCredsSettings == nil || rOutAcc.SystemAccessCredsSettings.JwtTtlDefault == nil {
		return 0
	}

	return *rOutAcc.SystemAccessCredsSettings.JwtTtlDefault
}
