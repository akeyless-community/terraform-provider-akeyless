package akeyless

import (
	"testing"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/stretchr/testify/require"
)

func TestExtractAerospikeTargetDetails(t *testing.T) {
	value, err := extractAerospikeTargetDetails(&akeyless_api.AerospikeTargetDetails{
		AerospikeAdminUsername: akeyless_api.PtrString("admin"),
		AerospikePassword:      akeyless_api.PtrString("password"),
		AerospikeHostname:      akeyless_api.PtrString("aerospike.example.com"),
		AerospikePort:          akeyless_api.PtrString("3000"),
		AerospikeNamespace:     akeyless_api.PtrString("test"),
		AerospikeClientSecret:  akeyless_api.PtrString("client-secret"),
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"admin_username":"admin","password":"password","hostname":"aerospike.example.com","port":"3000","namespace":"test","aerospike_client_secret":"client-secret"}`, value["aerospike_target_details"])
}

func TestExtractF5BigIpTargetDetails(t *testing.T) {
	value, err := extractF5BigIpTargetDetails(&akeyless_api.F5BigIpTargetDetails{
		Url:      akeyless_api.PtrString("https://f5.example.com"),
		Username: akeyless_api.PtrString("admin"),
		Password: akeyless_api.PtrString("password"),
	})
	require.NoError(t, err)
	require.JSONEq(t, `{"url":"https://f5.example.com","username":"admin","password":"password"}`, value["f5_big_ip_target_details"])
}
