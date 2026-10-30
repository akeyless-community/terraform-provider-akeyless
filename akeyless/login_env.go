package akeyless

import (
	"fmt"
	"os"
	"strings"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Environment variables used when the provider block has no login block.
const (
	envAccessType  = "AKEYLESS_ACCESS_TYPE"
	envAccessID    = "AKEYLESS_ACCESS_ID"
	envAccessKey   = "AKEYLESS_ACCESS_KEY"
	envEmail       = "AKEYLESS_EMAIL"
	envPassword    = "AKEYLESS_PASSWORD"
	envJwt         = "AKEYLESS_AUTH_JWT"
	envJwtFile     = "AKEYLESS_AUTH_JWT_FILE"
	envUidToken    = "AKEYLESS_AUTH_UID"
	envCertData    = "AKEYLESS_AUTH_CERT"
	envKeyData     = "AKEYLESS_AUTH_KEY"
	envToken       = "AKEYLESS_AUTH_TOKEN"
	envGcpAudience = "AKEYLESS_GCP_AUDIENCE"

	accessTypeToken = "token"
	accessTypeAuto  = "auto"
)

// supportedEnvAccessTypes lists the AKEYLESS_ACCESS_TYPE values, matching the Akeyless CLI access types.
var supportedEnvAccessTypes = []string{
	accessTypeAuto, common.ApiKey, common.Password, common.AwsIAM, common.Gcp, common.AzureAD,
	common.Jwt, common.Uid, common.Cert, accessTypeToken,
}

// accessTypeFrom returns the provider's access_type argument (which defaults to
// AKEYLESS_ACCESS_TYPE), or the environment variable when the schema has no such argument.
func accessTypeFrom(d *schema.ResourceData) string {
	if v, ok := d.GetOk("access_type"); ok {
		return v.(string)
	}
	return os.Getenv(envAccessType)
}

// jwtFromEnv returns the JWT from AKEYLESS_AUTH_JWT or from the file named by
// AKEYLESS_AUTH_JWT_FILE. Setting both is an error. The file is read on every call,
// so a token refreshed on disk is picked up by the next login.
func jwtFromEnv() (string, error) {
	inline, file := os.Getenv(envJwt), os.Getenv(envJwtFile)
	if inline != "" && file != "" {
		return "", fmt.Errorf("set only one of %s and %s", envJwt, envJwtFile)
	}
	if file == "" {
		return inline, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %v", envJwtFile, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// jwtDefaultFunc is the default for jwt_login.jwt.
func jwtDefaultFunc() (interface{}, error) {
	jwt, err := jwtFromEnv()
	if err != nil || jwt == "" {
		return nil, err
	}
	return jwt, nil
}

// loginFromEnv builds a login from environment variables. ok is false when the
// environment does not describe a login, so the caller can fall through to its own error.
//
// accessType selects the login method; its variables are then required. When it is empty
// or "auto", API key is used if AKEYLESS_ACCESS_ID and AKEYLESS_ACCESS_KEY are set (the
// existing behavior), otherwise JWT if AKEYLESS_ACCESS_ID and a JWT are set.
func loginFromEnv(accessType string) (login map[string]interface{}, lt loginType, ok bool, err error) {
	accessType = strings.ToLower(strings.TrimSpace(accessType))
	accessID := os.Getenv(envAccessID)

	if accessType == "" || accessType == accessTypeAuto {
		jwt, err := jwtFromEnv()
		if err != nil {
			return nil, "", false, err
		}
		switch {
		case accessID != "" && os.Getenv(envAccessKey) != "":
			accessType = common.ApiKey
		case accessID != "" && jwt != "":
			accessType = common.Jwt
		default:
			return nil, "", false, nil
		}
	}

	require := func(names ...string) error {
		var missing []string
		for _, n := range names {
			if os.Getenv(n) == "" {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("access_type %q requires environment variable(s): %s", accessType, strings.Join(missing, ", "))
		}
		return nil
	}

	switch accessType {
	case common.ApiKey, "access_key":
		if err := require(envAccessID, envAccessKey); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{"access_id": accessID, "access_key": os.Getenv(envAccessKey)}, ApiKeyLogin, true, nil
	case common.Password:
		if err := require(envEmail, envPassword); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{"admin_email": os.Getenv(envEmail), "admin_password": os.Getenv(envPassword)}, EmailLogin, true, nil
	case common.AwsIAM:
		if err := require(envAccessID); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{"access_id": accessID}, AwsIAMLogin, true, nil
	case common.Gcp:
		if err := require(envAccessID); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{"access_id": accessID, "audience": os.Getenv(envGcpAudience)}, GcpIAMLogin, true, nil
	case common.AzureAD:
		if err := require(envAccessID); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{"access_id": accessID}, AzureADLogin, true, nil
	case common.Jwt:
		if err := require(envAccessID); err != nil {
			return nil, "", false, err
		}
		jwt, err := jwtFromEnv()
		if err != nil {
			return nil, "", false, err
		}
		if jwt == "" {
			return nil, "", false, fmt.Errorf("access_type %q requires environment variable: %s or %s", accessType, envJwt, envJwtFile)
		}
		return map[string]interface{}{"access_id": accessID, "jwt": jwt}, JwtLogin, true, nil
	case common.Uid:
		if err := require(envUidToken); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{"access_id": accessID, "uid_token": os.Getenv(envUidToken)}, UidLogin, true, nil
	case common.Cert:
		if err := require(envAccessID, envCertData, envKeyData); err != nil {
			return nil, "", false, err
		}
		return map[string]interface{}{
			"access_id":      accessID,
			"cert_data":      os.Getenv(envCertData),
			"key_data":       os.Getenv(envKeyData),
			"cert_file_name": "",
			"key_file_name":  "",
		}, CertLogin, true, nil
	case accessTypeToken:
		// handled by tokenFromEnv before authentication
		return nil, "", false, fmt.Errorf("access_type %q requires environment variable: %s", accessType, envToken)
	default:
		return nil, "", false, fmt.Errorf("unsupported access_type %q, supported values: %s", accessType, strings.Join(supportedEnvAccessTypes, ", "))
	}
}

// tokenFromEnv returns AKEYLESS_AUTH_TOKEN when the access type is token and the
// provider block has no other login block.
func tokenFromEnv(d *schema.ResourceData) (string, bool) {
	if strings.ToLower(strings.TrimSpace(accessTypeFrom(d))) != accessTypeToken {
		return "", false
	}
	for _, block := range []string{"api_key_login", "email_login", "aws_iam_login", "gcp_login", "azure_ad_login", "jwt_login", "uid_login", "cert_login"} {
		if len(d.Get(block).([]interface{})) > 0 {
			return "", false
		}
	}
	token := os.Getenv(envToken)
	return token, token != ""
}
