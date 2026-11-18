package akeyless

import akeyless_api "github.com/akeylesslabs/akeyless-go/v5"

// ApiClient is the authenticated Akeyless handle shared by the SDK v2 and
// Framework providers. Kept tiny on purpose — just what ephemeral Open needs.
type ApiClient struct {
	Client *akeyless_api.V2ApiService
	Token  string
}
