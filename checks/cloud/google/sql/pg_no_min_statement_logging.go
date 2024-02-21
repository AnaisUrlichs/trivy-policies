package sql

import (
	"github.com/aquasecurity/trivy-policies/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckPgNoMinStatementLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0021",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-no-min-statement-logging",
		Summary:     "Ensure that logging of long statements is disabled.",
		Impact:      "Sensitive data could be exposed in the database logs.",
		Resolution:  "Disable minimum duration statement logging completely",
		Explanation: `Logging of statements which could contain sensitive data is not advised, therefore this setting should preclude all statements from being logged.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPgNoMinStatementLoggingGoodExamples,
			BadExamples:         terraformPgNoMinStatementLoggingBadExamples,
			Links:               terraformPgNoMinStatementLoggingLinks,
			RemediationMarkdown: terraformPgNoMinStatementLoggingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogMinDurationStatement.NotEqualTo(-1) {
				results.Add(
					"Database instance is configured to log statements.",
					instance.Settings.Flags.LogMinDurationStatement,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
