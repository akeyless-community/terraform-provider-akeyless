resource "akeyless_auth_method_saml" "saml_auth" {
  name                  = "auth-method-saml"
  unique_identifier     = "email"
  idp_metadata_xml_data = file("saml-metadata.xml")
}
