package akeyless

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

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/stretchr/testify/require"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
)

// generates base64 private key & certificate
func generateCertForTest(t *testing.T, size int) (string, string) {
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

func generateCertForTestWithKey(t *testing.T, size int, keyName string) (string, string) {

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

func generateKey(size int) string {
	key, _ := rsa.GenerateKey(rand.Reader, size)
	return createPrivateKeyBase64(key)
}

func generateKeyAndCsrForTest(size int) (string, string) {
	key, _ := rsa.GenerateKey(rand.Reader, size)

	privateKeyBase64 := createPrivateKeyBase64(key)
	csrBase64 := createCsrBase64(key)

	return privateKeyBase64, csrBase64
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

func createDfcKey(t *testing.T, name string) {

	client, token := prepareClient(t)

	body := akeyless_api.CreateDFCKey{
		Name:  name,
		Alg:   common.AlgRsa1024,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SplitLevel, 2)
	common.GetAkeylessPtr(&body.GenerateSelfSignedCertificate, true)
	common.GetAkeylessPtr(&body.CertificateTtl, 60)

	_, res, err := client.CreateDFCKey(context.Background()).Body(body).Execute()
	if err != nil && !isAlreadyExistError(err) {
		require.Fail(t, handleError(res, err).Error(), "failed to create key for test")
	}
}

func createProtectionKey(t *testing.T, name string) {

	client, token := prepareClient(t)

	body := akeyless_api.CreateDFCKey{
		Name:  name,
		Alg:   common.AlgAes128GCM,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SplitLevel, 2)

	_, res, err := client.CreateDFCKey(context.Background()).Body(body).Execute()
	if err != nil && !isAlreadyExistError(err) {
		require.Fail(t, handleError(res, err).Error(), "failed to create key for test")
	}
}

func getRsaPublicKey(t *testing.T, name string) akeyless_api.GetRSAPublicOutput {
	client, token := prepareClient(t)

	body := akeyless_api.GetRSAPublic{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.GetRSAPublic(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(res, err), "failed to get rsa public key for test")
	require.NotNil(t, rOut.Ssh)

	return rOut
}

func createPkiCertIssuer(t *testing.T, keyName, issuerName, destPath, cn, uriSan string) {

	client, token := prepareClient(t)

	body := akeyless_api.CreatePKICertIssuer{
		Name:          issuerName,
		SignerKeyName: keyName,
		Token:         &token,
		Ttl:           "300",
	}
	common.GetAkeylessPtr(&body.DestinationPath, destPath)
	common.GetAkeylessPtr(&body.ClientFlag, true)
	common.GetAkeylessPtr(&body.AllowedDomains, cn)
	common.GetAkeylessPtr(&body.AllowedUriSans, uriSan)

	_, res, err := client.CreatePKICertIssuer(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(res, err), "failed to create pki cert issuer for test")
}

func createSshCertIssuer(t *testing.T, keyName, issuerName, users string) {

	client, token := prepareClient(t)

	body := akeyless_api.CreateSSHCertIssuer{
		Name:          issuerName,
		SignerKeyName: keyName,
		Token:         &token,
		Ttl:           300,
	}
	common.GetAkeylessPtr(&body.AllowedUsers, users)

	_, res, err := client.CreateSSHCertIssuer(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(res, err), "failed to create ssh cert issuer for test")
}

func createCertificate(t *testing.T, certName, certBase64, keyBase64 string) {

	client, token := prepareClient(t)

	body := akeyless_api.CreateCertificate{
		Name:  certName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.CertificateData, certBase64)
	common.GetAkeylessPtr(&body.KeyData, keyBase64)

	_, res, err := client.CreateCertificate(context.Background()).Body(body).Execute()
	require.NoError(t, handleError(res, err), "failed to create certificate for test")
}

func deleteItem(t *testing.T, path string) {

	client, token := prepareClient(t)

	gsvBody := akeyless_api.DeleteItem{
		Name:              path,
		DeleteImmediately: akeyless_api.PtrBool(true),
		DeleteInDays:      akeyless_api.PtrInt64(-1),
		Token:             &token,
	}

	_, _, err := client.DeleteItem(context.Background()).Body(gsvBody).Execute()
	require.NoError(t, err)
}

func deleteItems(t *testing.T, path string) {

	client, token := prepareClient(t)

	gsvBody := akeyless_api.DeleteItems{
		Path:  path,
		Token: &token,
	}

	_, _, err := client.DeleteItems(context.Background()).Body(gsvBody).Execute()
	require.NoError(t, err)
}

func getProviderMeta() (*providerMeta, error) {

	apiGwAddress := os.Getenv("AKEYLESS_GATEWAY")
	if apiGwAddress == "" {
		apiGwAddress = publicApi
	}
	client := akeyless_api.NewAPIClient(&akeyless_api.Configuration{
		Servers: []akeyless_api.ServerConfiguration{
			{
				URL: apiGwAddress,
			},
		},
	}).V2Api

	authBody := akeyless_api.NewAuthWithDefaults()
	authBody.AccessId = akeyless_api.PtrString(os.Getenv("AKEYLESS_ACCESS_ID"))
	authBody.AccessKey = akeyless_api.PtrString(os.Getenv("AKEYLESS_ACCESS_KEY"))
	authBody.AccessType = akeyless_api.PtrString(common.ApiKey)

	ctx := context.Background()

	authOut, _, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return nil, err

	}
	token := authOut.GetToken()

	return &providerMeta{client, &token}, nil
}

func prepareClient(t *testing.T) (*akeyless_api.V2ApiService, string) {
	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	return client, token
}

func handleError(resp *http.Response, err error) error {
	if err == nil {
		return nil
	}

	var apiErr akeyless_api.GenericOpenAPIError
	if !errors.As(err, &apiErr) {
		return err
	}

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found: %w", err)
	}

	return errors.New(string(apiErr.Body()))
}

func isAlreadyExistError(err error) bool {
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
	return strings.Contains(msg, "AlreadyExists")
}
