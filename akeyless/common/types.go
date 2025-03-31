package common

const (
	ApiKey   = "api_key"
	Password = "password"
	AzureAD  = "azure_ad"
	AwsIAM   = "aws_iam"
	Gcp      = "gcp"
	Jwt      = "jwt"
	Uid      = "universal_identity"
	Cert     = "cert"

	StaticSecretType        = "STATIC_SECRET"
	DynamicStaticSecretType = "DYNAMIC_SECRET"
	RotatedSecretType       = "ROTATED_SECRET"

	AlgRsa1024   = "RSA1024"
	AlgAes128GCM = "AES128GCM"

	ClientTypeHeader    = "akeylessclienttype"
	TerraformClientType = "terraform"

	UserPassRotator       = "user-pass-rotator"
	ApiKeyRotator         = "api-key-rotator"
	LdapRotator           = "ldap-rotator"
	ServiceAccountRotator = "service-account-rotator"
	StorageAccountRotator = "azure-storage-account-rotator"

	UseExisting = "use-existing"

	TargetTypeAws   = "aws"
	TargetTypeAzure = "azure"
	TargetTypeGcp   = "gcp"
	TargetTypeK8s   = "k8s"
	TargetTypeVault = "hashi_vault"
)
