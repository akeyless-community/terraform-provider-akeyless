---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "akeyless_k8s_auth_config Resource - terraform-provider-akeyless"
subcategory: ""
description: |-
  K8S Auth config
---

# akeyless_k8s_auth_config (Resource)

K8S Auth config



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **access_id** (String) The access ID of the Kubernetes auth method
- **name** (String) K8S Auth config name

### Optional

- **config_encryption_key_name** (String) Encrypt K8S Auth config with following key
- **id** (String) The ID of this resource.
- **k8s_ca_cert** (String) Base-64 encoded certificate to use to call into the kubernetes API
- **k8s_host** (String) The URL of the kubernetes API server
- **k8s_issuer** (String) The Kubernetes JWT issuer name. If not set, kubernetes/serviceaccount will be used as an issuer.
- **signing_key** (String) The private key (in base64 encoded of the PEM format) associated with the public key defined in the Kubernetes auth
- **token_exp** (Number) Time in seconds of expiration of the Akeyless Kube Auth Method token
- **token_reviewer_jwt** (String) A Kubernetes service account JWT used to access the TokenReview API to validate other JWTs. If not set, the JWT submitted in the authentication process will be used to access the Kubernetes TokenReview API.


