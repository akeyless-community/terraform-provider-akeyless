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

	AlgRsa1024 = "RSA1024"

	ClientTypeHeader    = "akeylessclienttype"
	TerraformClientType = "terraform"
)
