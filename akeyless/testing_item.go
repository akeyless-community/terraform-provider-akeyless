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
	"os"
	"testing"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/stretchr/testify/require"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
)

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

	body := akeyless.CreateDFCKey{
		Name:  name,
		Alg:   common.AlgRsa1024,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SplitLevel, 2)
	common.GetAkeylessPtr(&body.GenerateSelfSignedCertificate, true)
	common.GetAkeylessPtr(&body.CertificateTtl, 60)

	_, _, err := client.CreateDFCKey(context.Background()).Body(body).Execute()
	require.NoError(t, err, "failed to create key for test")
}

func getRsaPublicKey(t *testing.T, name string) akeyless.GetRSAPublicOutput {
	client, token := prepareClient(t)

	body := akeyless.GetRSAPublic{
		Name:  name,
		Token: &token,
	}

	rOut, _, err := client.GetRSAPublic(context.Background()).Body(body).Execute()
	require.NoError(t, err, "failed to get rsa public key for test")
	require.NotNil(t, rOut.Ssh)

	return rOut
}

func createPkiCertIssuer(t *testing.T, keyName, issuerName, destPath, cn, uriSan string) {

	client, token := prepareClient(t)

	body := akeyless.CreatePKICertIssuer{
		Name:          issuerName,
		SignerKeyName: keyName,
		Token:         &token,
		Ttl:           300,
	}
	common.GetAkeylessPtr(&body.DestinationPath, destPath)
	common.GetAkeylessPtr(&body.ClientFlag, true)
	common.GetAkeylessPtr(&body.AllowedDomains, cn)
	common.GetAkeylessPtr(&body.AllowedUriSans, uriSan)

	_, _, err := client.CreatePKICertIssuer(context.Background()).Body(body).Execute()
	require.NoError(t, err, "failed to create pki cert issuer for test")
}

func createSshCertIssuer(t *testing.T, keyName, issuerName, users string) {

	client, token := prepareClient(t)

	body := akeyless.CreateSSHCertIssuer{
		Name:          issuerName,
		SignerKeyName: keyName,
		Token:         &token,
		Ttl:           300,
	}
	common.GetAkeylessPtr(&body.AllowedUsers, users)

	_, _, err := client.CreateSSHCertIssuer(context.Background()).Body(body).Execute()
	require.NoError(t, err, "failed to create ssh cert issuer for test")
}

func deleteItem(t *testing.T, path string) {

	client, token := prepareClient(t)

	gsvBody := akeyless.DeleteItem{
		Name:              path,
		DeleteImmediately: akeyless.PtrBool(true),
		DeleteInDays:      akeyless.PtrInt64(-1),
		Token:             &token,
	}

	_, _, err := client.DeleteItem(context.Background()).Body(gsvBody).Execute()
	require.NoError(t, err)
}

func deleteItems(t *testing.T, path string) {

	client, token := prepareClient(t)

	gsvBody := akeyless.DeleteItems{
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
	client := akeyless.NewAPIClient(&akeyless.Configuration{
		Servers: []akeyless.ServerConfiguration{
			{
				URL: apiGwAddress,
			},
		},
	}).V2Api

	authBody := akeyless.NewAuthWithDefaults()
	authBody.AccessId = akeyless.PtrString(os.Getenv("AKEYLESS_ACCESS_ID"))
	authBody.AccessKey = akeyless.PtrString(os.Getenv("AKEYLESS_ACCESS_KEY"))
	authBody.AccessType = akeyless.PtrString(common.ApiKey)

	ctx := context.Background()

	authOut, _, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return nil, err

	}
	token := authOut.GetToken()

	return &providerMeta{client, &token}, nil
}

func prepareClient(t *testing.T) (*akeyless.V2ApiService, string) {
	p, err := getProviderMeta()
	require.NoError(t, err)

	client := p.client
	token := *p.token

	return client, token
}
