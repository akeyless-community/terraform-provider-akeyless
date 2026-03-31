package testutils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const PublicAPI = "https://api.akeyless.io"

// Docker test infrastructure constants
const (
	DockerMysqlHost     = "mysql"
	DockerMysqlPort     = "3306"
	DockerMysqlUser     = "root"
	DockerMysqlPassword = "root_password"
	DockerMysqlDB       = "testdb"

	DockerPostgresHost     = "postgres"
	DockerPostgresPort     = "5432"
	DockerPostgresUser     = "postgres"
	DockerPostgresPassword = "postgres_password"
	DockerPostgresDB       = "testdb"

	DockerMongoHost     = "mongo"
	DockerMongoPort     = "27017"
	DockerMongoUser     = "admin"
	DockerMongoPassword = "mongo_password"
	DockerMongoDB       = "testdb"

	DockerMssqlHost     = "mssql"
	DockerMssqlPort     = "1433"
	DockerMssqlUser     = "sa"
	DockerMssqlPassword = "MssqlPass123!"
	DockerMssqlDB       = "master"

	DockerRedisHost     = "redis"
	DockerRedisPort     = "6379"
	DockerRedisUser     = "default"
	DockerRedisPassword = "redis_password"

	DockerCassandraHost     = "cassandra"
	DockerCassandraPort     = "9042"
	DockerCassandraUser     = "cassandra"
	DockerCassandraPassword = "cassandra"

	DockerRabbitmqURI      = "http://rabbitmq:15672"
	DockerRabbitmqUser     = "admin"
	DockerRabbitmqPassword = "rabbitmq_password"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

// NewProviderFactories returns a map of provider factories for use in acceptance tests.
func NewProviderFactories() map[string]func() (*schema.Provider, error) {
	return map[string]func() (*schema.Provider, error){
		"akeyless": func() (*schema.Provider, error) {
			return akeyless.Provider(), nil
		},
	}
}

// TestPath returns a namespaced test path.
func TestPath(testRunID, name string) string {
	return fmt.Sprintf("terraform-tests/%s/%v", testRunID, name)
}

// GetClient creates an SDK client and authenticates using env vars.
func GetClient() (*akeyless_api.V2ApiService, string, error) {
	apiGwAddress := os.Getenv("AKEYLESS_GATEWAY")
	if apiGwAddress == "" {
		apiGwAddress = PublicAPI
	}
	client := akeyless_api.NewAPIClient(&akeyless_api.Configuration{
		Servers: []akeyless_api.ServerConfiguration{
			{URL: apiGwAddress},
		},
	}).V2Api

	authBody := akeyless_api.NewAuthWithDefaults()
	authBody.AccessId = akeyless_api.PtrString(os.Getenv("AKEYLESS_ACCESS_ID"))
	authBody.AccessKey = akeyless_api.PtrString(os.Getenv("AKEYLESS_ACCESS_KEY"))
	authBody.AccessType = akeyless_api.PtrString(common.ApiKey)

	authOut, _, err := client.Auth(context.Background()).Body(*authBody).Execute()
	if err != nil {
		return nil, "", err
	}
	token := authOut.GetToken()
	return client, token, nil
}

func PrepareClient(t *testing.T) (*akeyless_api.V2ApiService, string) {
	client, token, err := GetClient()
	require.NoError(t, err)
	return client, token
}

func SkipIfNoGateway(t *testing.T) {
	t.Helper()
	gw := os.Getenv("AKEYLESS_GATEWAY")
	if gw == "" || gw == PublicAPI {
		t.Skip("skipping: requires local gateway (set AKEYLESS_GATEWAY)")
	}
}

// --- Certificate helpers ---

func GenerateCertForTest(t *testing.T, size int) (string, string) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject: pkix.Name{
			Country:      []string{"coun1"},
			Province:     []string{"prov1"},
			Locality:     []string{"loca1"},
			Organization: []string{"org1"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Minute),
		IsCA:        true,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, size)
	require.NoError(t, err)

	keyBase64 := createPrivateKeyBase64(caPrivKey)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	certBytes := pem.EncodeToMemory(&block)
	certBase64 := base64.StdEncoding.EncodeToString(certBytes)

	return keyBase64, certBase64
}

func GenerateCertForTestWithKey(t *testing.T, size int, keyName string) (string, string) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	require.NoError(t, err)

	cert := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: keyName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	signedCertBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	require.NoError(t, err)

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCertBytes})

	return base64.StdEncoding.EncodeToString(certPem), base64.StdEncoding.EncodeToString(signedCertBytes)
}

func GenerateKey(size int) string {
	key, _ := rsa.GenerateKey(rand.Reader, size)
	return createPrivateKeyBase64(key)
}

func GenerateKeyAndCsrForTest(size int) (string, string) {
	key, _ := rsa.GenerateKey(rand.Reader, size)
	privateKeyBase64 := createPrivateKeyBase64(key)
	csrBase64 := createCsrBase64(key)
	return privateKeyBase64, csrBase64
}

func GenerateCert(t *testing.T) string {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(20202),
		Subject: pkix.Name{
			Organization: []string{"akeyless.io"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 3, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return base64.StdEncoding.EncodeToString(certPEM)
}

func createPrivateKeyBase64(key *rsa.PrivateKey) string {
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	privateKeyBytes := pem.EncodeToMemory(&block)
	return base64.StdEncoding.EncodeToString(privateKeyBytes)
}

func createCsrBase64(key *rsa.PrivateKey) string {
	emailAddress := "test@example.com"
	subj := pkix.Name{
		CommonName:         "cn1",
		Country:            []string{"coun1"},
		Province:           []string{"prov1"},
		Locality:           []string{"loca1"},
		Organization:       []string{"org1"},
		OrganizationalUnit: []string{"unit1"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: emailAddress},
	})

	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{emailAddress},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, key)
	csrBlock := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	csr := pem.EncodeToMemory(&csrBlock)
	return base64.StdEncoding.EncodeToString(csr)
}

func ConvertPemCertToCrt(t *testing.T, certPem string) string {
	certBytes, err := base64.StdEncoding.DecodeString(certPem)
	require.NoError(t, err)

	block, _ := pem.Decode(certBytes)
	require.NotNil(t, block)

	crtBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	return base64.StdEncoding.EncodeToString(crtBytes)
}

// --- Item CRUD helpers ---

func CreateDfcKey(t *testing.T, name string) {
	client, token := PrepareClient(t)

	body := akeyless_api.CreateDFCKey{
		Name:  name,
		Alg:   common.AlgRsa1024,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SplitLevel, 2)
	common.GetAkeylessPtr(&body.GenerateSelfSignedCertificate, true)
	common.GetAkeylessPtr(&body.CertificateTtl, 60)

	_, res, err := client.CreateDFCKey(context.Background()).Body(body).Execute()
	if err != nil && !IsAlreadyExistError(err) {
		require.Fail(t, common.HandleError("can't create dfc key for test", res, err).Error())
	}
}

func CreateProtectionKey(t *testing.T, name string) {
	client, token := PrepareClient(t)

	body := akeyless_api.CreateDFCKey{
		Name:  name,
		Alg:   common.AlgAes128GCM,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SplitLevel, 2)

	_, res, err := client.CreateDFCKey(context.Background()).Body(body).Execute()
	if err != nil && !IsAlreadyExistError(err) {
		require.Fail(t, common.HandleError("can't create protection key for test", res, err).Error())
	}
}

func GetRsaPublicKey(t *testing.T, name string) *akeyless_api.GetRSAPublicOutput {
	client, token := PrepareClient(t)

	body := akeyless_api.GetRSAPublic{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GetRSAPublic(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't get rsa public key for test", res, err))
	require.NotNil(t, rOut.Ssh)

	return rOut
}

func CreatePkiCertIssuer(t *testing.T, keyName, issuerName, destPath, cn, uriSan string) {
	client, token := PrepareClient(t)

	body := akeyless_api.CreatePKICertIssuer{
		Name:  issuerName,
		Token: &token,
		Ttl:   "300",
	}
	common.GetAkeylessPtr(&body.SignerKeyName, keyName)
	common.GetAkeylessPtr(&body.DestinationPath, destPath)
	common.GetAkeylessPtr(&body.ClientFlag, true)
	common.GetAkeylessPtr(&body.AllowedDomains, cn)
	common.GetAkeylessPtr(&body.AllowedUriSans, uriSan)

	_, res, err := client.CreatePKICertIssuer(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create pki cert issuer for test", res, err))
}

func CreateSshCertIssuer(t *testing.T, keyName, issuerName, users string) {
	client, token := PrepareClient(t)

	body := akeyless_api.CreateSSHCertIssuer{
		Name:          issuerName,
		SignerKeyName: keyName,
		Token:         &token,
		Ttl:           300,
	}
	common.GetAkeylessPtr(&body.AllowedUsers, users)
	common.GetAkeylessPtr(&body.ExternalUsername, "false")

	_, res, err := client.CreateSSHCertIssuer(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create ssh cert issuer for test", res, err))
}

func CreateCertificate(t *testing.T, certName, certBase64, keyBase64 string) {
	client, token := PrepareClient(t)

	body := akeyless_api.CreateCertificate{
		Name:  certName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.CertificateData, certBase64)
	common.GetAkeylessPtr(&body.KeyData, keyBase64)

	_, res, err := client.CreateCertificate(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create certificate for test", res, err))
}

type TestSecret struct {
	SecretName  string
	SecretType  string
	Format      string
	Value       string
	Username    string
	Password    string
	CustomField map[string]string
	InjectUrl   []string
}

func CreateSecret(t *testing.T, secret *TestSecret) {
	client, token := PrepareClient(t)

	body := akeyless_api.CreateSecret{
		Name:  secret.SecretName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Type, secret.SecretType)
	common.GetAkeylessPtr(&body.Format, secret.Format)
	common.GetAkeylessPtr(&body.Value, secret.Value)
	common.GetAkeylessPtr(&body.Username, secret.Username)
	common.GetAkeylessPtr(&body.Password, secret.Password)
	body.CustomField = &secret.CustomField
	common.GetAkeylessPtr(&body.InjectUrl, secret.InjectUrl)

	_, res, err := client.CreateSecret(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create secret for test", res, err))
}

func DeleteItemIfExists(t *testing.T, path string) {
	client, token := PrepareClient(t)

	gsvBody := akeyless_api.DeleteItem{
		Name:              path,
		DeleteImmediately: akeyless_api.PtrBool(true),
		DeleteInDays:      akeyless_api.PtrInt64(-1),
		Token:             &token,
	}

	client.DeleteItem(context.Background()).Body(gsvBody).Execute()
}

func DeleteItem(t *testing.T, path string) {
	client, token := PrepareClient(t)

	gsvBody := akeyless_api.DeleteItem{
		Name:              path,
		DeleteImmediately: akeyless_api.PtrBool(true),
		DeleteInDays:      akeyless_api.PtrInt64(-1),
		Token:             &token,
	}

	_, _, err := client.DeleteItem(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "delete protection") || strings.Contains(errStr, "delete_protection") || strings.Contains(errStr, "403") {
			updateBody := akeyless_api.UpdateItem{
				Name:             path,
				Token:            &token,
				DeleteProtection: akeyless_api.PtrString("false"),
			}
			_, _, updateErr := client.UpdateItem(context.Background()).Body(updateBody).Execute()
			if updateErr != nil {
				t.Logf("failed to remove delete protection: %v", updateErr)
			} else {
				_, _, retryErr := client.DeleteItem(context.Background()).Body(gsvBody).Execute()
				if retryErr == nil {
					return
				}
				err = retryErr
			}
		}
	}
}

func DeleteItems(t *testing.T, path string) {
	client, token := PrepareClient(t)

	gsvBody := akeyless_api.DeleteItems{
		Token: &token,
	}
	common.GetAkeylessPtr(&gsvBody.Path, path)

	_, _, err := client.DeleteItems(context.Background()).Body(gsvBody).Execute()
	require.NoError(t, err)
}

func IsAlreadyExistError(err error) bool {
	if err != nil {
		if containsAlreadyExist(err.Error()) {
			return true
		}
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) && containsAlreadyExist(string(apiErr.Body())) {
			return true
		}
	}
	return false
}

func containsAlreadyExist(msg string) bool {
	return strings.Contains(msg, "AlreadyExists") || strings.Contains(msg, "Conflict")
}

type TestMysqlDynamicSecret struct {
	SecretName string
	Username   string
	Password   string
	Host       string
	Port       string
	DbName     string
}

func CreateMysqlDynamicSecret(t *testing.T, secret *TestMysqlDynamicSecret) {
	client, token := PrepareClient(t)

	body := akeyless_api.DynamicSecretCreateMySql{
		Name:  secret.SecretName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.MysqlUsername, secret.Username)
	common.GetAkeylessPtr(&body.MysqlPassword, secret.Password)
	common.GetAkeylessPtr(&body.MysqlHost, secret.Host)
	common.GetAkeylessPtr(&body.MysqlPort, secret.Port)
	common.GetAkeylessPtr(&body.MysqlDbname, secret.DbName)

	_, res, err := client.DynamicSecretCreateMySql(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create mysql dynamic secret for test", res, err))
}

type TestMysqlRotatedSecret struct {
	SecretName string
	TargetName string
}

func CreateMysqlRotatedSecret(t *testing.T, secret *TestMysqlRotatedSecret) {
	client, token := PrepareClient(t)

	body := akeyless_api.RotatedSecretCreateMysql{
		Name:        secret.SecretName,
		TargetName:  secret.TargetName,
		RotatorType: "target",
		Token:       &token,
	}
	common.GetAkeylessPtr(&body.AuthenticationCredentials, "use-target-creds")

	_, res, err := client.RotatedSecretCreateMysql(context.Background()).Body(body).Execute()
	require.NoError(t, common.HandleError("can't create mysql rotated secret for test", res, err))
}

// --- Test runner helpers (parameterized on providerFactories) ---

func TestItemResource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), itemPath string, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
			Check: resource.ComposeTestCheckFunc(
				CheckItemExistsRemotely(itemPath),
			),
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps:             steps,
	})
}

func TestFolderResource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), folderName string, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
			Check: resource.ComposeTestCheckFunc(
				CheckFolderExistsRemotely(folderName),
			),
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps:             steps,
	})
}

func TestGatewayConfigResource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), config, configUpdate string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
			},
			{
				Config: configUpdate,
			},
		},
	})
}

func TestTargetResource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), secretPath string, configs ...string) {
	steps := make([]resource.TestStep, len(configs))
	for i, config := range configs {
		steps[i] = resource.TestStep{
			Config: config,
			Check: resource.ComposeTestCheckFunc(
				CheckTargetExistsRemotely(secretPath),
			),
		}
	}

	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      CheckTargetDestroyed,
		Steps:             steps,
	})
}

func TesTargetResource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), config, configUpdate, secretPath string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      CheckTargetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					CheckTargetExistsRemotely(secretPath),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					CheckTargetExistsRemotely(secretPath),
				),
			},
		},
	})
}

func TestAuthMethodResource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), config, configUpdate, path string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		CheckDestroy:      CheckAuthMethodDestroyed,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					CheckMethodExistsRemotely(path),
				),
			},
			{
				Config: configUpdate,
				Check: resource.ComposeTestCheckFunc(
					CheckMethodExistsRemotely(path),
				),
			},
		},
	})
}

type TestGatewayAllowedAccessInput struct {
	Config, ConfigUpdate, ItemPath, PermissionsOnCreate, PermissionsOnUpdate, EmailSubClaimsOnCreate, EmailSubClaimsOnUpdate string
}

func TestGatewayAllowedAccessRunFunc(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), input *TestGatewayAllowedAccessInput) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: input.Config,
				Check: resource.ComposeTestCheckFunc(
					CheckGatewayAllowedAccessExistsAndValidateDetails(t, input.ItemPath, input.PermissionsOnCreate, input.EmailSubClaimsOnCreate),
				),
			},
			{
				Config: input.ConfigUpdate,
				Check: resource.ComposeTestCheckFunc(
					CheckGatewayAllowedAccessExistsAndValidateDetails(t, input.ItemPath, input.PermissionsOnUpdate, input.EmailSubClaimsOnUpdate),
				),
			},
		},
	})
}

func TesItemDataSource(t *testing.T, providerFactories map[string]func() (*schema.Provider, error), config, outputName string, params []string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  CheckOutputNotEmpty(outputName, params),
			},
		},
	})
}

// --- Check functions (use GetClient instead of testAccProvider) ---

func CheckItemExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.DescribeItem{
			Name:         path,
			ShowVersions: akeyless_api.PtrBool(false),
			Token:        &token,
		}

		_, _, err = client.DescribeItem(context.Background()).Body(gsvBody).Execute()
		return err
	}
}

func CheckFolderExistsRemotely(folder string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.FolderGet{
			Name:  folder,
			Token: &token,
		}

		_, _, err = client.FolderGet(context.Background()).Body(gsvBody).Execute()
		return err
	}
}

func CheckTargetExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.TargetGet{
			Name:  path,
			Token: &token,
		}

		_, _, err = client.TargetGet(context.Background()).Body(gsvBody).Execute()
		return err
	}
}

func CheckMethodExistsRemotely(path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.AuthMethodGet{
			Name:  path,
			Token: &token,
		}

		_, _, err = client.AuthMethodGet(context.Background()).Body(gsvBody).Execute()
		return err
	}
}

var CheckTargetDestroyed = func(s *terraform.State) error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if strings.HasPrefix(rs.Type, "akeyless_target") {
			body := akeyless_api.TargetGet{
				Name:  rs.Primary.ID,
				Token: &token,
			}
			_, res, err := client.TargetGet(context.Background()).Body(body).Execute()
			if err == nil {
				return fmt.Errorf("target %s still exists", rs.Primary.ID)
			}
			if res != nil && res.StatusCode != 404 {
				return fmt.Errorf("target %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
			}
		}
	}
	return nil
}

var CheckAuthMethodDestroyed = func(s *terraform.State) error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if strings.HasPrefix(rs.Type, "akeyless_auth_method") {
			body := akeyless_api.AuthMethodGet{
				Name:  rs.Primary.ID,
				Token: &token,
			}
			_, res, err := client.AuthMethodGet(context.Background()).Body(body).Execute()
			if err == nil {
				return fmt.Errorf("auth method %s still exists", rs.Primary.ID)
			}
			if res != nil && res.StatusCode != 404 {
				return fmt.Errorf("auth method %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
			}
		}
	}
	return nil
}

func CheckGatewayAllowedAccessExistsAndValidateDetails(t *testing.T, allowedAccessName, permissions, emailSubClaims string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		ctx := context.Background()
		body := akeyless_api.GatewayGetAllowedAccess{
			Name:  allowedAccessName,
			Token: &token,
		}

		output, _, err := client.GatewayGetAllowedAccess(ctx).Body(body).Execute()
		require.NoError(t, err)
		require.ElementsMatch(t, output.Permissions, strings.Split(permissions, ","), "permissions is not as expected")

		emailSubClaimsString, ok := (*output.SubClaims)["email"]
		require.True(t, ok, "Sub-Claims value is not as expected")
		require.ElementsMatch(t, emailSubClaimsString, strings.Split(emailSubClaims, ","), "sub-claims value is not as expected")

		return nil
	}
}

func CheckOutputNotEmpty(name string, params []string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ms := s.RootModule()
		outputs, ok := ms.Outputs[name]
		if !ok || outputs == nil {
			return nil
		}
		values := outputs.Value.(map[string]interface{})

		for _, param := range params {
			rs, ok := values[param]
			if !ok {
				return fmt.Errorf("output '%s' not found", param)
			}
			output, ok := rs.(string)
			if !ok || output == "" {
				return fmt.Errorf("output '%s' not found", param)
			}
		}
		return nil
	}
}

// --- Role check helpers ---

func CheckRoleExistsRemotely(t *testing.T, roleName, authMethodPath string, rulesNum int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		association := res.GetRoleAuthMethodsAssoc()[0]
		assert.Equal(t, authMethodPath, *association.AuthMethodName, "auth method name mismatch")
		for k, v := range *association.AuthMethodSubClaims {
			assert.Equal(t, "groups", k)
			assert.Equal(t, strings.Split("admins,developers", ","), v)
		}

		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}
		if rulesNum != len(rules.GetPathRules()) {
			fmt.Println("rulesNum:", res.GetRules())
			fmt.Println("len(rules.GetPathRules()):", rules.GetPathRules())
		}

		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		exists := false
		for _, r := range rules.GetPathRules() {
			if strings.Contains(r.GetPath(), "/terraform-tests/*") {
				exists = true
				assert.Equal(t, []string{"read"}, r.GetCapabilities())
				assert.Equal(t, "auth-method-rule", r.GetType())
			}
		}

		assert.True(t, exists)

		return nil
	}
}

func CheckAssocExistsRemotely(t *testing.T, roleName, authMethodPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		association := res.GetRoleAuthMethodsAssoc()[0]
		assert.Equal(t, authMethodPath, *association.AuthMethodName, "auth method name mismatch")
		for k, v := range *association.AuthMethodSubClaims {
			assert.Equal(t, "groups", k)
			assert.Equal(t, strings.Split("admins,developers", ","), v)
		}
		return nil
	}
}

func CheckAssocExistsRemotely2(t *testing.T, roleName, authMethodPath string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		association := res.GetRoleAuthMethodsAssoc()[0]
		assert.Equal(t, authMethodPath, *association.AuthMethodName, "auth method name mismatch")
		assert.Equal(t, 2, len(*association.AuthMethodSubClaims), "auth method name mismatch")
		for k, v := range *association.AuthMethodSubClaims {
			if k == "groups" {
				assert.Equal(t, strings.Split("admins", ","), v)
			} else if k == "groups2" {
				assert.Equal(t, strings.Split("dogs,rats", ","), v)
			} else {
				t.Fail()
			}
		}
		return nil
	}
}

func CheckAddRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}
		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		return nil
	}
}

func CheckUpdateRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return checkUpdateRole(t, roleName, 1, rulesNum)
}

func CheckUpdateRoleRemotelyNoAcc(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return checkUpdateRole(t, roleName, 0, rulesNum)
}

func checkUpdateRole(t *testing.T, roleName string, accnum, rulesNum int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, accnum, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}
		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		return nil
	}
}

func CheckRemoveRoleRemotely(t *testing.T, roleName string, rulesNum int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}

		res, _, err := client.GetRole(context.Background()).Body(gsvBody).Execute()
		assert.NoError(t, err)
		assert.Equal(t, 1, len(res.GetRoleAuthMethodsAssoc()), "can't find Auth Method association")
		rules := res.GetRules()

		if common.IsCICDEnv() {
			rulesNum++
		}
		assert.Equal(t, rulesNum, len(rules.GetPathRules()))

		return nil
	}
}

// --- Delete helpers ---

func DeleteTarget(t *testing.T, name string) {
	client, token, err := GetClient()
	require.NoError(t, err)

	gsvBody := akeyless_api.DeleteTarget{
		Name:  name,
		Token: &token,
	}

	client.DeleteTarget(context.Background()).Body(gsvBody).Execute()
}

func DeleteRole(path string) error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	gsvBody := akeyless_api.DeleteRole{
		Name:  path,
		Token: &token,
	}

	_, res, err := client.DeleteRole(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		if res != nil && res.StatusCode == http.StatusNotFound {
			return nil
		}
		return common.HandleError("can't delete role", res, err)
	}
	fmt.Println("deleted", path)
	return nil
}

func CreateTestAuthMethod(path string) error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	gsvBody := akeyless_api.CreateAuthMethod{
		Name:  path,
		Token: &token,
	}

	_, _, err = client.CreateAuthMethod(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		fmt.Println("error create auth method:", err)
		return err
	}
	fmt.Println("created auth method:", path)
	return nil
}

func DeleteAuthMethod(path string, authMethodType string) error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	gsvBody := akeyless_api.AuthMethodDelete{
		Name:  path,
		Token: &token,
	}

	_, _, err = client.AuthMethodDelete(context.Background()).Body(gsvBody).Execute()
	if err != nil {
		if strings.Contains(err.Error(), "404") && !strings.HasPrefix(path, "/") {
			pathWithSlash := "/" + path
			gsvBody.Name = pathWithSlash
			_, _, err2 := client.AuthMethodDelete(context.Background()).Body(gsvBody).Execute()
			if err2 == nil {
				fmt.Println("deleted auth method:", pathWithSlash)
				return nil
			}
			err = err2
		}
	} else {
		fmt.Println("deleted auth method:", path)
		return nil
	}

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "delete protection") || strings.Contains(errStr, "delete_protection") {
			fmt.Println("delete protection enabled, removing protection and retrying...")

			switch authMethodType {
			case "api_key":
				updateBody := akeyless_api.AuthMethodUpdateApiKey{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateApiKey(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "aws_iam":
				updateBody := akeyless_api.AuthMethodUpdateAwsIam{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateAwsIam(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "azure_ad":
				updateBody := akeyless_api.AuthMethodUpdateAzureAD{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateAzureAD(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "cert":
				updateBody := akeyless_api.AuthMethodUpdateCert{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateCert(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "gcp":
				updateBody := akeyless_api.AuthMethodUpdateGcp{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateGcp(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "k8s":
				updateBody := akeyless_api.AuthMethodUpdateK8s{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateK8s(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "ldap":
				updateBody := akeyless_api.AuthMethodUpdateLdap{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateLdap(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "oauth2":
				updateBody := akeyless_api.AuthMethodUpdateOauth2{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateOauth2(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "oidc":
				updateBody := akeyless_api.AuthMethodUpdateOIDC{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateOIDC(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "saml":
				updateBody := akeyless_api.AuthMethodUpdateSAML{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateSAML(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "universal_identity":
				updateBody := akeyless_api.AuthMethodUpdateUniversalIdentity{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateUniversalIdentity(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "kerberos":
				updateBody := akeyless_api.AuthMethodUpdateKerberos{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateKerberos(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			case "oci":
				updateBody := akeyless_api.AuthMethodUpdateOCI{Name: path, Token: &token, DeleteProtection: akeyless_api.PtrString("false")}
				_, _, updateErr := client.AuthMethodUpdateOCI(context.Background()).Body(updateBody).Execute()
				if updateErr != nil {
					return err
				}
			}

			_, _, retryErr := client.AuthMethodDelete(context.Background()).Body(gsvBody).Execute()
			if retryErr != nil {
				return retryErr
			}
			fmt.Println("deleted auth method:", path)
			return nil
		}

		return err
	}

	return nil
}

// CheckRoleDestroyed checks that a role is deleted after destroy.
var CheckRoleDestroyed = func(s *terraform.State) error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	for _, rs := range s.RootModule().Resources {
		if rs.Type == "akeyless_role" {
			body := akeyless_api.GetRole{
				Name:  rs.Primary.ID,
				Token: &token,
			}
			_, res, err := client.GetRole(context.Background()).Body(body).Execute()
			if err == nil {
				return fmt.Errorf("role %s still exists", rs.Primary.ID)
			}
			if res != nil && res.StatusCode != 404 {
				return fmt.Errorf("role %s: unexpected status %d", rs.Primary.ID, res.StatusCode)
			}
		}
	}
	return nil
}
