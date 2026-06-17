package akeyless

import (
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func setPasswordPolicyReadFields(d *schema.ResourceData, passwordLength *int64, useCapitalLetters, useLowerLetters, useNumbers, useSpecialCharacters *bool) error {
	if passwordLength != nil {
		if err := d.Set("password_length", strconv.Itoa(int(*passwordLength))); err != nil {
			return err
		}
	}
	if useCapitalLetters != nil {
		if err := d.Set("use_capital_letters", strconv.FormatBool(*useCapitalLetters)); err != nil {
			return err
		}
	}
	if useLowerLetters != nil {
		if err := d.Set("use_lower_letters", strconv.FormatBool(*useLowerLetters)); err != nil {
			return err
		}
	}
	if useNumbers != nil {
		if err := d.Set("use_numbers", strconv.FormatBool(*useNumbers)); err != nil {
			return err
		}
	}
	if useSpecialCharacters != nil {
		if err := d.Set("use_special_characters", strconv.FormatBool(*useSpecialCharacters)); err != nil {
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
	var useCapitalLetters, useLowerLetters, useNumbers, useSpecialCharacters *bool
	if details.PasswordPolicyInfo != nil {
		if passwordLength == nil {
			passwordLength = details.PasswordPolicyInfo.PasswordLength
		}
		useCapitalLetters = details.PasswordPolicyInfo.UseCapitalLetters
		useLowerLetters = details.PasswordPolicyInfo.UseLowerLetters
		useNumbers = details.PasswordPolicyInfo.UseNumbers
		useSpecialCharacters = details.PasswordPolicyInfo.UseSpecialCharacters
	}

	return setPasswordPolicyReadFields(d, passwordLength, useCapitalLetters, useLowerLetters, useNumbers, useSpecialCharacters)
}

func setRotatedSecretPasswordPolicyReadFields(d *schema.ResourceData, generalInfo *akeyless_api.ItemGeneralInfo) error {
	if generalInfo == nil || generalInfo.PasswordPolicy == nil {
		return nil
	}

	return setPasswordPolicyReadFields(
		d,
		generalInfo.PasswordPolicy.PasswordLength,
		generalInfo.PasswordPolicy.UseCapitalLetters,
		generalInfo.PasswordPolicy.UseLowerLetters,
		generalInfo.PasswordPolicy.UseNumbers,
		generalInfo.PasswordPolicy.UseSpecialCharacters,
	)
}
