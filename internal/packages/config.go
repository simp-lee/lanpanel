package packages

import (
	"fmt"
	"strconv"
	"strings"
)

const transactionRoot = "/var/lib/lanpanel/packages/transactions/"

func RenderAPTConfiguration(plan Plan) ([]byte, []byte, error) {
	if err := ValidatePlan(plan); err != nil {
		return nil, nil, err
	}
	root := transactionRoot + plan.TransactionID + "/"
	sourcePath := root + "sources.list"
	proxy := "DIRECT"
	if plan.Proxy != nil {
		proxy = plan.Proxy.URL
	}
	ioTimeout := plan.ReadTimeout
	if plan.ConnectTimeout < ioTimeout {
		ioTimeout = plan.ConnectTimeout
	}
	seconds := strconv.FormatInt(int64(ioTimeout.Seconds()), 10)
	lines := []string{
		`APT::Architecture "amd64";`,
		`APT::Architectures { "amd64"; };`,
		`APT::Get::AllowUnauthenticated "false";`,
		`APT::Sandbox::User "root";`,
		`Acquire::AllowDowngradeToInsecureRepositories "false";`,
		`Acquire::AllowInsecureRepositories "false";`,
		`Acquire::Retries "0";`,
		`Acquire::http::Timeout "` + seconds + `";`,
		`Acquire::https::Timeout "` + seconds + `";`,
		`Dir::Cache::archives "` + root + `archives/";`,
		`Dir::State::lists "/var/lib/apt/lists/";`,
	}
	if plan.Proxy != nil {
		lines = append(lines, `Acquire::http::Proxy "`+proxy+`";`, `Acquire::https::Proxy "`+proxy+`";`)
	}
	if len(plan.Repositories) != 0 {
		lines = append(lines, `Dir::Etc::netrc "`+root+`auth.conf";`, `Dir::Etc::netrcparts "-";`, `Dir::Etc::preferences "`+root+`preferences";`, `Dir::Etc::preferencesparts "-";`)

		lines = append(lines, `Dir::Etc::sourceparts "-";`, `Dir::Etc::sourcelist "`+sourcePath+`";`)
	}
	config := []byte(strings.Join(lines, "\n") + "\n")
	sourceLines := []string{}
	for _, repository := range plan.Repositories {
		sourceLines = append(sourceLines, fmt.Sprintf("deb [arch=amd64 signed-by=%s] %s %s %s", repository.KeyringPath, repository.URI, repository.Suite, strings.Join(repository.Components, " ")))
	}
	sources := []byte(strings.Join(sourceLines, "\n"))
	if len(sources) != 0 {
		sources = append(sources, '\n')
	}
	return config, sources, nil
}
