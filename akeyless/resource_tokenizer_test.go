package akeyless

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"
)

const (
	CREDIT_CARD = "1111-2222-3333-4444"
)

func TestTokenizerCreateUpdate(t *testing.T) {
	t.Parallel()

	name := "test_tokenizer"
	itemPath := testPath(name)

	config := fmt.Sprintf(`
		resource "akeyless_tokenizer" "%v" {
			name 				= "%v"
			template_type     	= "CreditCard"
			tweak_type        	= "Internal"
			description         = "aaaa"
			tag               	= ["t1","t2"]
			delete_protection 	= "true"
		}
	`, name, itemPath)

	configUpdate := fmt.Sprintf(`
		resource "akeyless_tokenizer" "%v" {
			name 				= "%v"
			template_type     	= "CreditCard"
			tweak_type        	= "Internal"
			description         = "bbbb"
			tag               	= ["t3","t4"]
			delete_protection 	= "false"
		}
	`, name, itemPath)

	tesItemResource(t, config, configUpdate, itemPath)
}

func TestTokenizerCustomType(t *testing.T) {
	t.Parallel()

	name := "custom_internal"
	itemPath := testPath(name)

	configResource := fmt.Sprintf(`
		resource "akeyless_tokenizer" "%v" {
			name 				= "%v"
			template_type     	= "Custom"
			tweak_type        	= "Internal"
			alphabet          	= "0123456789"
			pattern           	= "(\\d{4})[-]?(\\d{4})[-]?(\\d{4})[-]?(?:\\d{4})"
			decoding_template 	= "$1|$2|$3|$4"
		}
	`, name, itemPath)
	configTokenize := dataSourceTokenizeConfig(name, itemPath, "")
	configOutput1 := outputTokenizeConfig(name)
	configDetokenize := dataSourceDetokenizeConfig(name, itemPath, false)
	configOutput2 := outputDetokenizeConfig(name)

	config := fmt.Sprintf(`
		%v
		%v
		%v
		%v
		%v
	`, configResource, configTokenize, configOutput1, configDetokenize,
		configOutput2)

	expTokenizeRgx := `(\d{4})[-](\d{4})[-](\d{4})[-]4444`
	expDetokenize := "1111|2222|3333|"
	testTokenizer(t, config, expTokenizeRgx, expDetokenize)
}

func TestTokenizerInternal(t *testing.T) {
	t.Parallel()

	name := "tokenizer_internal"
	itemPath := testPath(name)

	configResource := resourceTokenizerConfig(name, itemPath, "Internal")
	configTokenize := dataSourceTokenizeConfig(name, itemPath, "")
	configOutput1 := outputTokenizeConfig(name)
	configDetokenize := dataSourceDetokenizeConfig(name, itemPath, false)
	configOutput2 := outputDetokenizeConfig(name)

	config := fmt.Sprintf(`
		%v
		%v
		%v
		%v
		%v
	`, configResource, configTokenize, configOutput1, configDetokenize,
		configOutput2)

	expTokenizeRgx := `(\d{4})[-]?(\d{4})[-]?(\d{4})[-]?(\d{4})`
	expDetokenize := CREDIT_CARD
	testTokenizer(t, config, expTokenizeRgx, expDetokenize)
}

func TestTokenizerMasking(t *testing.T) {
	t.Parallel()

	name := "tokenizer_masking"
	itemPath := testPath(name)

	configResource := resourceTokenizerConfig(name, itemPath, "Masking")
	configTokenize := dataSourceTokenizeConfig(name, itemPath, "")
	configOutput := outputTokenizeConfig(name)

	config := fmt.Sprintf(`
		%v
		%v
		%v
	`, configResource, configTokenize, configOutput)

	expTokenizeRgx := `(\d{4})[-]?(\d{4})[-]?(\d{4})[-]?(\d{4})`
	expDetokenize := ""
	testTokenizer(t, config, expTokenizeRgx, expDetokenize)
}

func TestTokenizerGenerated(t *testing.T) {
	t.Parallel()

	name := "tokenizer_generated"
	itemPath := testPath(name)

	configResource := resourceTokenizerConfig(name, itemPath, "Generated")
	configTokenize := dataSourceTokenizeConfig(name, itemPath, "")
	configOutput1 := outputTokenizeConfig(name)
	configOutputTweak := outputTweakConfig(name)
	configDetokenize := dataSourceDetokenizeConfig(name, itemPath, true)
	configOutput2 := outputDetokenizeConfig(name)

	config := fmt.Sprintf(`
		%v
		%v
		%v
		%v
		%v
		%v
	`, configResource, configTokenize, configOutput1, configOutputTweak,
		configDetokenize, configOutput2)

	expTokenizeRgx := `(\d{4})[-]?(\d{4})[-]?(\d{4})[-]?(\d{4})`
	expDetokenize := CREDIT_CARD
	testTokenizer(t, config, expTokenizeRgx, expDetokenize)
}

func TestTokenizerSupplied(t *testing.T) {
	t.Parallel()

	tweakBytes := make([]byte, 7)
	_, err := rand.Read(tweakBytes)
	require.NoError(t, err)

	tweak := base64.StdEncoding.EncodeToString(tweakBytes)

	name := "tokenizer_supplied"
	itemPath := testPath(name)

	configResource := resourceTokenizerConfig(name, itemPath, "Supplied")
	configTokenize := dataSourceTokenizeConfig(name, itemPath, tweak)
	configOutput1 := outputTokenizeConfig(name)
	configDetokenize := dataSourceDetokenizeConfig(name, itemPath, true)
	configOutput2 := outputDetokenizeConfig(name)

	config := fmt.Sprintf(`
		%v
		%v
		%v
		%v
		%v
	`, configResource, configTokenize, configOutput1, configDetokenize,
		configOutput2)

	expTokenizeRgx := `(\d{4})[-]?(\d{4})[-]?(\d{4})[-]?(\d{4})`
	expDetokenize := CREDIT_CARD
	testTokenizer(t, config, expTokenizeRgx, expDetokenize)
}

func testTokenizer(t *testing.T, config, expTokenizeRgx, expDetokenize string) {
	resource.Test(t, resource.TestCase{
		ProviderFactories: providerFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check:  CheckTokenizeDetokenize(t, expTokenizeRgx, expDetokenize),
			},
		},
	})
}

func CheckTokenizeDetokenize(t *testing.T, expTokenizeRgx, expDetokenize string) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		// check tokenize
		tokenized := s.Modules[0].Outputs["tokenized"]
		require.NotNil(t, tokenized)

		tokenizePattern := regexp.MustCompile(expTokenizeRgx)
		match := tokenizePattern.MatchString(tokenized.String())
		require.True(t, match, "tokenize results are different")

		// check detokenize
		if expDetokenize != "" {
			detokenized := s.Modules[0].Outputs["detokenized"]
			require.NotNil(t, detokenized)

			require.Equal(t, expDetokenize, detokenized.Value.(string), "detokenize results are different")
		}
		return nil
	}
}

func resourceTokenizerConfig(name, path, tweakType string) string {
	return fmt.Sprintf(`
	resource "akeyless_tokenizer" "%v" {
		name 				= "%v"
		template_type     	= "CreditCard"
		tweak_type        	= "%v"
	}
	`, name, path, tweakType)
}

func dataSourceTokenizeConfig(name, path, tweak string) string {
	tweakConf := ""
	if tweak != "" {
		tweakConf = fmt.Sprintf(`tweak = "%v"`, tweak)
	}

	return fmt.Sprintf(`
	data "akeyless_tokenize" "%v" {
		tokenizer_name  = "%v"
		plaintext       = "1111-2222-3333-4444"
		%v

		depends_on = [
		  akeyless_tokenizer.%v,
		]
	}
	`, name, path, tweakConf, name)
}

func dataSourceDetokenizeConfig(name, path string, withTweak bool) string {
	tweakConf := ""
	if withTweak {
		tweakConf = fmt.Sprintf("tweak = data.akeyless_tokenize.%v.tweak", name)
	}

	return fmt.Sprintf(`
	data "akeyless_detokenize" "%v" {
		tokenizer_name  = "%v"
		ciphertext      = data.akeyless_tokenize.%v.result
		%v

		depends_on = [
		  data.akeyless_tokenize.%v,
		]
	}
	`, name, path, name, tweakConf, name)
}

func outputTokenizeConfig(name string) string {
	return fmt.Sprintf(`
	output "tokenized" {
		value = data.akeyless_tokenize.%v.result
	}
	`, name)
}

func outputDetokenizeConfig(name string) string {
	return fmt.Sprintf(`
	output "detokenized" {
		value = data.akeyless_detokenize.%v.result
	}
	`, name)
}

func outputTweakConfig(name string) string {
	return fmt.Sprintf(`
	output "tweak" {
		value = data.akeyless_tokenize.%v.tweak
	}
	`, name)
}
