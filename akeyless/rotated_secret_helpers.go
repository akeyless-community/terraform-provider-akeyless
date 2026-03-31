package akeyless

import (
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func setRotatorType(d *schema.ResourceData, rotatorType string) error {
	mapped := rotatorType
	switch rotatorType {
	case common.UserPassRotator:
		mapped = "password"
	case common.ApiKeyRotator:
		mapped = "api-key"
	case common.LdapRotator:
		mapped = "ldap"
	case common.StorageAccountRotator:
		mapped = "azure-storage-account"
	case common.TargetRotator:
		mapped = "target"
	}

	return d.Set("rotator_type", mapped)
}
