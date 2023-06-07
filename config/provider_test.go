package config

import (
	"reflect"
	"testing"

	"github.com/gookit/config/v2"
)

func Test_ReadConfig(t *testing.T) {
	type args struct {
		configFile string
	}
	tests := []struct {
		name              string
		args              args
		wantConfiguration Configuration
		wantErr           bool
	}{
		{
			"Read config",
			args{"data/config_test.yaml"},
			Configuration{
				Server: Server{
					Port:        3000,
					TemplateDir: "views/",
					StaticDir:   "views/static",
				},
				Verifier: Verifier{
					Did:           "did:key:somekey",
					TirAddress:    "https://test.dev/trusted_issuer/v3/issuers/",
					SessionExpiry: 30,
					PolicyConfig: Policies{
						DefaultPolicies: PolicyMap{
							"SignaturePolicy": {},
							"TrustedIssuerRegistryPolicy": {
								"registryAddress": "waltId.com",
							},
						},
						CredentialTypeSpecificPolicies: map[string]PolicyMap{
							"gx:compliance": {
								"ValidFromBeforePolicy": {},
							},
						},
					},
				}, SSIKit: SSIKit{
					AuditorURL: "http://waltid:7003",
				},
				Logging: Logging{
					Level:       "DEBUG",
					JsonLogging: true,
					LogRequests: true,
					PathsToSkip: []string{"/health"},
				},
				ConfigRepo: ConfigRepo{
					ConfigEndpoint: "",
					Services: map[string]Service{
						"testService": {
							Scope: []string{"VerifiableCredential", "CustomerCredential"},
							TrustedParticipants: map[string][]string{
								"VerifiableCredential": {"https://tir-pdc.gaia-x.fiware.dev"},
								"CustomerCredential":   {"https://tir-pdc.gaia-x.fiware.dev"},
							},
							TrustedIssuers: map[string][]string{
								"VerifiableCredential": {"https://tir-pdc.gaia-x.fiware.dev"},
								"CustomerCredential":   {"https://tir-pdc.gaia-x.fiware.dev"},
							}}},
				},
			},
			false,
		}, {
			"Defaults only",
			args{"data/empty_test.yaml"},
			Configuration{
				Server: Server{Port: 8080,
					TemplateDir: "views/",
					StaticDir:   "views/static/",
				},
				Verifier: Verifier{Did: "",
					TirAddress:    "",
					SessionExpiry: 30,
				}, SSIKit: SSIKit{
					AuditorURL: "",
				},
				Logging: Logging{
					Level:       "INFO",
					JsonLogging: true,
					LogRequests: true,
					PathsToSkip: nil,
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.Reset()
			gotConfiguration, err := ReadConfig(tt.args.configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("readConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotConfiguration, tt.wantConfiguration) {
				t.Errorf("readConfig() = %v, want %v", gotConfiguration, tt.wantConfiguration)
			}
		})
	}
}