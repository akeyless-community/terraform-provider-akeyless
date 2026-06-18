package akeyless

import (
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func setPasswordPolicyReadFields(d *schema.ResourceData, passwordLength *int64) error {
	if passwordLength != nil {
		if err := d.Set("password_length", strconv.Itoa(int(*passwordLength))); err != nil {
			return err
		}
	}

	return nil
}

func setDynamicSecretPasswordPolicyReadFields(d *schema.ResourceData, details *akeyless_api.DSProducerDetails) error {
	if details == nil {
		return nil
	}

	passwordLength := details.PasswordLength
	if details.PasswordPolicyInfo != nil && passwordLength == nil {
		passwordLength = details.PasswordPolicyInfo.PasswordLength
	}

	return setPasswordPolicyReadFields(d, passwordLength)
}

func setRotatedSecretPasswordPolicyReadFields(d *schema.ResourceData, generalInfo *akeyless_api.ItemGeneralInfo) error {
	if generalInfo == nil || generalInfo.PasswordPolicy == nil {
		return nil
	}

	return setPasswordPolicyReadFields(d, generalInfo.PasswordPolicy.PasswordLength)
}
