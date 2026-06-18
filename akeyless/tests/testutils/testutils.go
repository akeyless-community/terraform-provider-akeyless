package testutils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// dockerHost returns the host to use for reaching a Docker service from the
// gateway container. On macOS (Docker Desktop) standalone containers don't
// share a docker-compose network, so host.docker.internal is used. On Linux
// (CI) the docker-compose service name is used directly.
func dockerHost(serviceName string) string {
	if v := os.Getenv("DOCKER_" + strings.ToUpper(serviceName) + "_HOST"); v != "" {
		return v
	}
	if runtime.GOOS == "darwin" {
		return "host.docker.internal"
	}
	return serviceName
}

// Docker test infrastructure defaults.
// On macOS hosts default to host.docker.internal (works with standalone containers).
// On Linux (CI) they default to docker-compose service names.
// Override any value via env var (e.g. DOCKER_MYSQL_HOST).
var (
	DockerMysqlHost     = dockerHost("mysql")
	DockerMysqlPort     = envOr("DOCKER_MYSQL_PORT", "3306")
	DockerMysqlUser     = envOr("DOCKER_MYSQL_USER", "root")
	DockerMysqlPassword = envOr("DOCKER_MYSQL_PASSWORD", "password")
	DockerMysqlDB       = envOr("DOCKER_MYSQL_DB", "mysql")

	DockerPostgresHost     = dockerHost("postgres")
	DockerPostgresPort     = envOr("DOCKER_POSTGRES_PORT", "5432")
	DockerPostgresUser     = envOr("DOCKER_POSTGRES_USER", "postgres")
	DockerPostgresPassword = envOr("DOCKER_POSTGRES_PASSWORD", "postgres_password")
	DockerPostgresDB       = envOr("DOCKER_POSTGRES_DB", "testdb")

	DockerMongoHost     = dockerHost("mongo")
	DockerMongoPort     = envOr("DOCKER_MONGO_PORT", "27017")
	DockerMongoUser     = envOr("DOCKER_MONGO_USER", "admin")
	DockerMongoPassword = envOr("DOCKER_MONGO_PASSWORD", "mongo_password")
	DockerMongoDB       = envOr("DOCKER_MONGO_DB", "testdb")

	DockerMssqlHost     = dockerHost("mssql")
	DockerMssqlPort     = envOr("DOCKER_MSSQL_PORT", "1433")
	DockerMssqlUser     = envOr("DOCKER_MSSQL_USER", "sa")
	DockerMssqlPassword = envOr("DOCKER_MSSQL_PASSWORD", "MssqlPass123!")
	DockerMssqlDB       = envOr("DOCKER_MSSQL_DB", "master")

	DockerRedisHost     = dockerHost("redis")
	DockerRedisPort     = envOr("DOCKER_REDIS_PORT", "6379")
	DockerRedisUser     = envOr("DOCKER_REDIS_USER", "default")
	DockerRedisPassword = envOr("DOCKER_REDIS_PASSWORD", "redis_password")

	DockerCassandraHost     = dockerHost("cassandra")
	DockerCassandraPort     = envOr("DOCKER_CASSANDRA_PORT", "9042")
	DockerCassandraUser     = envOr("DOCKER_CASSANDRA_USER", "cassandra")
	DockerCassandraPassword = envOr("DOCKER_CASSANDRA_PASSWORD", "cassandra")

	DockerRabbitmqURI      = envOr("DOCKER_RABBITMQ_URI", "http://"+dockerHost("rabbitmq")+":15672")
	DockerRabbitmqUser     = envOr("DOCKER_RABBITMQ_USER", "admin")
	DockerRabbitmqPassword = envOr("DOCKER_RABBITMQ_PASSWORD", "rabbitmq_password")

	VaultAddr  = "http://127.0.0.1:18200"
	VaultToken = "test"

	// DockerVaultAddr is the Vault URL reachable from inside the Docker network (gateway container).
	DockerVaultAddr = "http://" + dockerHost("vault") + ":8200"

	// decoded value: {"dummy": "test"}
	GCP_KEY = "eyJkdW1teSI6ICJ0ZXN0In0="
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
// Retries on transient connection errors (EOF, connection reset) to
// survive Docker gateway restarts during CI.
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

	var lastErr error
	for attempt := range 5 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		authOut, _, err := client.Auth(context.Background()).Body(*authBody).Execute()
		if err == nil {
			return client, authOut.GetToken(), nil
		}
		lastErr = err
		if !isTransientError(err) {
			return nil, "", err
		}
	}
	return nil, "", lastErr
}

func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "connection refused")
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

func DisableCache() error {
	client, token, err := GetClient()
	if err != nil {
		return fmt.Errorf("get client: %w", err)
	}

	body := akeyless_api.GatewayUpdateCache{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.EnableCache, "false")
	common.GetAkeylessPtr(&body.EnableProactive, "false")

	_, resp, err := client.GatewayUpdateCache(context.Background()).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't disable cache", resp, err)
	}

	return nil
}

func SkipIfNoVault(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(VaultAddr + "/v1/sys/health")
	if err != nil {
		t.Skip("skipping: vault not reachable at " + VaultAddr)
	}
	resp.Body.Close()
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

func CheckFolderSyncExistsRemotely(folder, uscName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		gsvBody := akeyless_api.FolderGet{
			Name:  folder,
			Token: &token,
		}

		rOut, _, err := client.FolderGet(context.Background()).Body(gsvBody).Execute()
		if err != nil {
			return err
		}
		if rOut.Folder == nil {
			return fmt.Errorf("folder not found: %s", folder)
		}

		normalizedUscName := strings.TrimPrefix(uscName, "/")
		for _, syncConfig := range rOut.Folder.UscSyncConfigs {
			if syncConfig.UscItemName == nil {
				continue
			}
			if strings.TrimPrefix(*syncConfig.UscItemName, "/") == normalizedUscName {
				return nil
			}
		}

		return fmt.Errorf("folder sync not found for folder %s and usc %s", folder, uscName)
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

// ExpectedRule describes a single path rule (regular or access rule) as stored
// on the server.
type ExpectedRule struct {
	Type         string
	Path         string
	Capabilities []string
}

// CheckRoleRulesRemotely validates the role's full rule set (including access
// rules such as search-rule/reports-rule/isi-rule) against the server, so the
// test fails when the applied rules do not match what is actually stored
// remotely.
func CheckRoleRulesRemotely(t *testing.T, roleName string, expected []ExpectedRule) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, token, err := GetClient()
		if err != nil {
			return err
		}

		res, _, err := client.GetRole(context.Background()).Body(akeyless_api.GetRole{
			Name:  roleName,
			Token: &token,
		}).Execute()
		assert.NoError(t, err)

		rules := res.GetRules()
		remoteRules := rules.GetPathRules()

		for _, exp := range expected {
			found := false
			for _, r := range remoteRules {
				if r.GetType() == exp.Type && r.GetPath() == exp.Path {
					found = true
					assert.ElementsMatch(t, exp.Capabilities, r.GetCapabilities(),
						"capabilities mismatch for rule type=%s path=%s", exp.Type, exp.Path)
					break
				}
			}
			assert.True(t, found, "expected rule not found on remote: type=%s path=%s", exp.Type, exp.Path)
		}

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

func GenerateSelfSignedCertBase64(t *testing.T) (certB64, keyB64 string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return base64.StdEncoding.EncodeToString(certPEM), base64.StdEncoding.EncodeToString(keyPEM)
}

// EnableSRA sends a bastion keep-alive to the Gator service so that the
// gateway's cluster is marked as SRA-active. Without this, any gateway
// config update that touches SshBastion/Global/WebBastion fields is rejected
// with "sra is not activate for cluster ...".
func EnableSRA() error {
	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName == "" {
		clusterName = "defaultCluster"
	}

	accessID := os.Getenv("AKEYLESS_ACCESS_ID")
	accessKey := os.Getenv("AKEYLESS_ACCESS_KEY")
	if accessID == "" || accessKey == "" {
		return fmt.Errorf("AKEYLESS_ACCESS_ID and AKEYLESS_ACCESS_KEY must be set")
	}

	gatorDNS, authDNS, err := getServiceDNS()
	if err != nil {
		return fmt.Errorf("get service DNS: %w", err)
	}
	fmt.Printf("[EnableSRA] gator=%s auth=%s cluster=%s\n", gatorDNS, authDNS, clusterName)

	uamCreds, err := authenticateUAM(authDNS, accessID, accessKey)
	if err != nil {
		return fmt.Errorf("authenticate UAM: %w", err)
	}
	fmt.Printf("[EnableSRA] got UAM creds (len=%d)\n", len(uamCreds))

	if err := waitForGatewayRemoteAccessConfig(); err != nil {
		return fmt.Errorf("wait for gateway cluster registration: %w", err)
	}

	if err := sendBastionKeepAlive(gatorDNS, uamCreds, clusterName); err != nil {
		return fmt.Errorf("send bastion keep-alive: %w", err)
	}
	fmt.Println("[EnableSRA] bastion keep-alive sent successfully")

	// The SRA-active marking has a short TTL on the Gator side, so a single
	// keep-alive expires before the full suite finishes. Refresh it
	// periodically in the background to keep the cluster SRA-active.
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := sendBastionKeepAlive(gatorDNS, uamCreds, clusterName); err != nil {
				fmt.Printf("[EnableSRA] keep-alive refresh failed: %v\n", err)
			}
		}
	}()
	return nil
}

func getServiceDNS() (gatorDNS, authDNS string, err error) {
	resp, err := http.Get(PublicAPI + "/status")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	var status struct {
		GatorDNS string `json:"gator_dns"`
		AuthDNS  string `json:"auth_dns"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		return "", "", err
	}
	return status.GatorDNS, status.AuthDNS, nil
}

func authenticateUAM(authDNS, accessID, accessKeyB64 string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(accessKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode access key: %w", err)
	}

	privKey := restoreECDSAKey(seed)

	serverTime, err := getAuthTime(authDNS)
	if err != nil {
		return "", fmt.Errorf("get auth time: %w", err)
	}

	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceBytes)

	stringToSign := "signatureForTemporaryCredential;access_id=" + accessID +
		";nonce=" + nonce + ";time=" + strconv.FormatInt(serverTime, 10)

	digest := sha256.Sum256([]byte(stringToSign))
	sig, err := privKey.Sign(rand.Reader, digest[:], nil)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	params := url.Values{}
	params.Set("access_id", accessID)
	params.Set("timestamp", strconv.FormatInt(serverTime, 10))
	params.Set("nonce", nonce)
	params.Set("signature", sigB64)
	params.Set("creds_expiry", "1800") // 30 minutes

	authURL := authDNS + "/auth-uam?" + params.Encode()
	resp, err := http.Get(authURL)
	if err != nil {
		return "", fmt.Errorf("auth-uam request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("auth-uam read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth-uam status %d: %s", resp.StatusCode, body)
	}

	var creds struct {
		UAMCreds string `json:"uam_creds"`
	}
	if err := json.Unmarshal(body, &creds); err != nil {
		return "", fmt.Errorf("auth-uam unmarshal: %w", err)
	}
	if creds.UAMCreds == "" {
		return "", fmt.Errorf("auth-uam returned empty uam_creds, body: %s", string(body[:min(len(body), 200)]))
	}
	return creds.UAMCreds, nil
}

func waitForGatewayRemoteAccessConfig() error {
	client, token, err := GetClient()
	if err != nil {
		return err
	}

	body := akeyless_api.GatewayGetRemoteAccess{
		Token: &token,
	}

	var lastErr error
	for attempt := range 10 {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}

		_, resp, err := client.GatewayGetRemoteAccess(context.Background()).Body(body).Execute()
		if err == nil {
			return nil
		}
		lastErr = common.HandleError("gateway remote access config not ready", resp, err)
	}

	return lastErr
}

func restoreECDSAKey(seed []byte) *ecdsa.PrivateKey {
	k := new(big.Int).SetBytes(seed)
	prv := new(ecdsa.PrivateKey)
	prv.PublicKey.Curve = elliptic.P256()
	prv.D = k
	prv.PublicKey.X, prv.PublicKey.Y = elliptic.P256().ScalarBaseMult(k.Bytes())
	return prv
}

func getAuthTime(authDNS string) (int64, error) {
	resp, err := http.Get(authDNS + "/time")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("time status %d: %s", resp.StatusCode, body)
	}

	var t struct {
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(body, &t); err != nil {
		return 0, err
	}
	return t.Time, nil
}

func sendBastionKeepAlive(gatorDNS, uamCreds, clusterName string) error {
	bastionInfo := map[string]interface{}{
		"cluster_name":         clusterName,
		"instance_id":          fmt.Sprintf("terraform-test-%d", time.Now().UnixNano()),
		"version":              "1.0.0",
		"bastion_type":         "ztb",
		"has_gateway_identity": true,
	}

	reqBody, err := json.Marshal(bastionInfo)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, gatorDNS+"/bastions/keep-alive", bytes.NewReader(reqBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("akeylessuam-accesscreds", uamCreds)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bastion keep-alive status %d: %s", resp.StatusCode, body)
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
