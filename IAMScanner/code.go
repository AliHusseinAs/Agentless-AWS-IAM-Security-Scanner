package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/open-policy-agent/opa/rego"
)

type CISMITREMapping struct {
	CISID   string `json:"cis_id"`
	CISName string `json:"cis_name"`
	MITREID string `json:"mitre_id"`
	MITRE   string `json:"mitre"`
}
type Mitre struct {
	ID   string
	Name string
}

func configuration() (*iam.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("Failed to get AWS user credentials: %v", err)
	}

	iamClient := iam.NewFromConfig(cfg)
	return iamClient, nil
}

func checkPolicy(policy, policyPackage string, input map[string]any) (string, any, error) {
	policyPath := filepath.Join("policies", policy)
	policyContent, err := os.ReadFile(policyPath)
	if err != nil {
		return "", "", fmt.Errorf("Failed to read the .rego file: %v", err)
	}
	r := rego.New(
		rego.Query(policyPackage+".compliant"),
		rego.Module(policy, string(policyContent)),
		rego.Input(input),
	)
	rs, err := r.Eval(context.TODO())
	if err != nil {
		return "", "", fmt.Errorf("OPA Eval Error: %v", err)
	}

	if len(rs) == 0 {
		return "No result from OPA", "", nil
	}
	// result is the compliant condition wether true or false
	result := rs[0].Expressions[0].Value
	res := policy
	return res, result, nil

}

// CIS 1.3
func AccountAccessKey() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", 0, fmt.Errorf("Paniced:%v", err)
	}

	res, err := client.GetAccountSummary(context.TODO(), &iam.GetAccountSummaryInput{})
	if err != nil {
		return "", 0, fmt.Errorf("Paniced2: %v", err)
	}
	var accountPressence int32
	for k, v := range res.SummaryMap {
		if k == "AccountAccessKeysPresent" {
			accountPressence = v
			break
		}
	}
	input := map[string]any{
		"AccountAccessKeysPresent": accountPressence,
	}

	policy, checker, err := checkPolicy("1_3.rego",
		"data.aws.iam.scanner.cis._1_3.benchmark", input)
	return policy, checker, err

}

// CIS 1.4
func MfaEnabledBenchmark() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Paniced:%v", err)
	}

	res, err := client.GetAccountSummary(context.TODO(), &iam.GetAccountSummaryInput{})
	if err != nil {
		return "", "", fmt.Errorf("Paniced2: %v", err)
	}
	AccountMFA := res.SummaryMap["AccountMFAEnabled"]
	AccountPass := res.SummaryMap["AccountPasswordPresent"]

	input := map[string]any{
		"AccountMFAEnabled":      AccountMFA,
		"AccountPasswordPresent": AccountPass,
	}
	policyName, policyCheck, err := checkPolicy("1_4.rego",
		"data.aws.iam.scanner.cis._1_4.benchmark.compliant", input)
	return policyName, policyCheck, nil
}

// CIS 1.6
func rootUse() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to configure: %w", err)
	}

	for {
		res, err := client.GenerateCredentialReport(context.TODO(),
			&iam.GenerateCredentialReportInput{})
		if err != nil {
			return "", "", fmt.Errorf("Failed to generate the report: %w", err)
		}
		state := res.State
		if state == "COMPLETE" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	res2, err := client.GetCredentialReport(context.TODO(),
		&iam.GetCredentialReportInput{})
	if err != nil {
		return "", "", fmt.Errorf("Failed to get credentials report: %w", err)
	}
	reader := csv.NewReader(strings.NewReader(string(res2.Content)))
	records, err := reader.ReadAll()
	if err != nil {
		return "", "", fmt.Errorf("Failed to read the CSV report: %w", err)
	}
	var daySince float64
	header := records[0]
	for _, row := range records[1:] {
		rowData := make(map[string]string)
		for i, col := range header {
			if i < len(row) {
				rowData[col] = row[i]
			}
		}
		if rowData["user"] == "<root_account>" {
			lastUsed := rowData["password_last_used"]
			t, err := time.Parse(time.RFC3339, lastUsed)
			if err != nil {
				return "", "", fmt.Errorf("Failed to parse the time :%w", err)
			} else {
				daySince = time.Since(t).Hours() / 24
			}
		}

	}

	input := map[string]any{
		"DaysUsed": daySince,
	}
	policy, checker, err := checkPolicy("1_6.rego",
		"data.aws.iam.scanner.cis._1_6.benchmark.compliant", input)
	return policy, checker, err

}

// CIS 1.7
func minPassPolicy() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to create IAM client: %w", err)
	}
	res, err := client.GetAccountPasswordPolicy(context.TODO(),
		&iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var notFoundErr *types.NoSuchEntityException
		if errors.As(err, &notFoundErr) {
			input := map[string]any{
				"MinimumPasswordLength": 0,
			}
			policy, checker, err := checkPolicy("1_7.rego",
				"data.aws.iam.scanner.cis._1_7.benchmark.compliant", input)
			return policy, checker, err
		}
		return "", "", fmt.Errorf("Error in getting the account password policy: %w", err)
	}
	k := res.PasswordPolicy.MinimumPasswordLength
	input := map[string]any{
		"MinimumPasswordLength": k,
	}
	policy, checker, err := checkPolicy("1_7.rego",
		"data.aws.iam.scanner.cis._1_7.benchmark.compliant", input)
	return policy, checker, err

}

// CIS 1.8
func reusePassPolicy() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to create IAM client: %v", err)
	}

	res, err := client.GetAccountPasswordPolicy(context.TODO(),
		&iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var notFoundErr *types.NoSuchEntityException
		if errors.As(err, &notFoundErr) {
			input := map[string]any{
				"PasswordReusePrevention": 0,
			}
			policy, checker, err := checkPolicy("1_8.rego",
				"data.aws.iam.scanner.cis._1_8.benchmark.compliant", input)
			return policy, checker, err

		}
		return "", "", fmt.Errorf("Failed to get account password policy: %v", err)
	}
	k := res.PasswordPolicy.MinimumPasswordLength
	input := map[string]any{
		"PasswordReusePrevention": k,
	}
	policy, checker, err := checkPolicy("1_8.rego",
		"data.aws.iam.scanner.cis._1_8.benchmark.compliant", input)
	return policy, checker, err
}

// CIS 1.9
func IamUserMFA() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to configure: %w", err)
	}

	for {
		res, err := client.GenerateCredentialReport(context.TODO(),
			&iam.GenerateCredentialReportInput{})
		if err != nil {
			return "", "", fmt.Errorf("Failed to generate the report: %w", err)
		}
		state := res.State
		if state == "COMPLETE" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	res2, err := client.GetCredentialReport(context.TODO(),
		&iam.GetCredentialReportInput{})
	if err != nil {
		return "", "", fmt.Errorf("Failed to get credentials report: %w", err)
	}
	reader := csv.NewReader(strings.NewReader(string(res2.Content)))
	records, err := reader.ReadAll()
	if err != nil {
		return "", "", fmt.Errorf("Failed to read the CSV report: %w", err)
	}
	var MfaCondition int64 = 0
	header := records[0]
	for _, row := range records[1:] {
		rowData := make(map[string]string)
		for i, col := range header {
			if i < len(row) {
				rowData[col] = row[i]
			}
		}

		if rowData["password_enabled"] == "true" && rowData["mfa_active"] != "true" {
			MfaCondition = 1
		}
	}

	input := map[string]any{
		"MfaEnabled": MfaCondition,
	}

	policy, checker, err := checkPolicy("1_9.rego",
		"data.aws.iam.scanner.cis._1_9.benchmark.compliant", input)
	return policy, checker, err

}

// CIS 1.11

func useCreden() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to configure: %w", err)
	}

	for {
		res, err := client.GenerateCredentialReport(context.TODO(),
			&iam.GenerateCredentialReportInput{})
		if err != nil {
			return "", "", fmt.Errorf("Failed to generate the report: %w", err)
		}
		state := res.State
		if state == "COMPLETE" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	res2, err := client.GetCredentialReport(context.TODO(),
		&iam.GetCredentialReportInput{})
	if err != nil {
		return "", "", fmt.Errorf("Failed to get credentials report: %w", err)
	}
	reader := csv.NewReader(strings.NewReader(string(res2.Content)))
	records, err := reader.ReadAll()
	if err != nil {
		return "", "", fmt.Errorf("Failed to read the CSV report: %w", err)
	}
	var daySince float64
	header := records[0]
	for _, row := range records[1:] {
		rowData := make(map[string]string)
		for i, col := range header {
			if i < len(row) {
				rowData[col] = row[i]
			}
		}
		if rowData["password_enabled"] == "true" && rowData["user"] != "<root_account>" {
			lastUsed := rowData["password_last_used"]
			t, err := time.Parse(time.RFC3339, lastUsed)
			if err != nil {
				return "", "", fmt.Errorf("Failed to parse the time :%w", err)
			} else {
				daySince = time.Since(t).Hours() / 24
			}
		}

	}

	input := map[string]any{
		"DaysUsed": daySince,
	}
	policy, checker, err := checkPolicy("1_11.rego",
		"data.aws.iam.scanner.cis._1_11.benchmark.compliant", input)
	return policy, checker, err

}

// CIS 1.12

func oneAccessKey() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to create IAM client: %w", err)
	}

	res, err := client.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return "", "", fmt.Errorf("Failed to list users: %w", err)
	}
	activeKey := 0
	for _, user := range res.Users {
		username := *user.UserName
		res2, err := client.ListAccessKeys(context.TODO(), &iam.ListAccessKeysInput{
			UserName: &username,
		})
		if err != nil {
			return "", "", fmt.Errorf("Failed to list access keys for the users: %w", err)
		}
		for _, key := range res2.AccessKeyMetadata {
			if key.Status == "Active" {
				activeKey++
			}
		}
	}
	input := map[string]any{
		"activeKey": activeKey,
	}
	policy, check, err := checkPolicy("1_12.rego",
		"data.aws.iam.scanner.cis._1_12.benchmark.compliant", input)
	if err != nil {
		return "", "", err
	}

	return policy, check, nil

}

// CIS 1.14

func groupPerm() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to create IAM Client: %w", err)
	}
	res, err := client.ListUsers(context.TODO(), &iam.ListUsersInput{})
	if err != nil {
		return "", "", fmt.Errorf("Failed to list users: %w", err)
	}
	for _, user := range res.Users {
		username := *user.UserName
		res2, err := client.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{
			UserName: &username,
		})
		if err != nil {
			return "", "", fmt.Errorf("Failed to list userNames: %w", err)
		}

		k := res2.AttachedPolicies
		if len(k) > 0 {
			input := map[string]any{
				"Result": 1,
			}
			policy, check, err := checkPolicy("1_14.rego",
				"data.aws.iam.scanner.cis._1_14.benchmark.compliant", input)
			return policy, check, err
		}
	}
	input := map[string]any{
		"Result": 0,
	}
	policy, check, err := checkPolicy("1_14.rego",
		"data.aws.iam.scanner.cis._1_14.benchmark.compliant", input)
	if err != nil {
		return "", "", fmt.Errorf("Failed to check against OPA policies: %w", err)
	}

	return policy, check, nil

}

// CIS 1.16
func supportAccess() (string, any, error) {
	client, err := configuration()
	if err != nil {
		return "", "", fmt.Errorf("Failed to create IAM client: %w", err)
	}
	res, err := client.ListPolicies(context.TODO(), &iam.ListPoliciesInput{})
	if err != nil {
		return "", "", fmt.Errorf("Failed to list policies: %w", err)
	}
	for _, k := range res.Policies {
		if aws.ToString(k.PolicyName) == "AWSSupportAccess" {
			if aws.ToInt32(k.AttachmentCount) == 0 {
				input := map[string]any{
					"policyRoles": 1,
				}
				policy, check, err := checkPolicy("1_16.rego", "data.aws.iam.scanner.cis._1_16.benchmark.compliant", input)
				if err != nil {
					return "", "", fmt.Errorf("OPA Error: %w", err)
				}
				return policy, check, nil
			}

		}
	}
	input := map[string]any{
		"policyRoles": 0,
	}
	policy, check, err := checkPolicy("1_16.rego", "data.aws.iam.scanner.cis._1_16.benchmark.compliant", input)
	if err != nil {
		return "", "", fmt.Errorf("OPA Error: %w", err)
	}
	return policy, check, nil

}
func main() {

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := []CISMITREMapping{}

	auditFuncs := []func() (string, any, error){
		AccountAccessKey,    // CIS 1.3
		MfaEnabledBenchmark, // CIS 1.4
		rootUse,             // CIS 1.6
		minPassPolicy,       // CIS 1.7
		reusePassPolicy,     // CIS 1.8
		IamUserMFA,          // CIS 1.9
		useCreden,           // CIS 1.11
		oneAccessKey,        // CIS 1.12
		groupPerm,           // CIS 1.14
		supportAccess,       // CIS 1.16

	}
	cisPolicyInfo := map[string]string{
		"1_3.rego":  "CIS 1.3: Ensure no 'root' user account access key exists",
		"1_4.rego":  "CIS 1.4: Ensure MFA is enabled for the 'root' user account",
		"1_6.rego":  "CIS 1.6: Eliminate use of the 'root' user for administrative and daily tasks",
		"1_7.rego":  "CIS 1.7: Ensure IAM password policy requires minimum length of 14 or greater",
		"1_8.rego":  "CIS 1.8: Ensure IAM password policy prevents password reuse",
		"1_9.rego":  "CIS 1.9: Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
		"1_11.rego": "CIS 1.11: Ensure credentials unused for 45 days or more are disabled",
		"1_12.rego": "CIS 1.12: Ensure there is only one active access key for any single IAM user",
		"1_14.rego": "CIS 1.14: Ensure IAM users receive permissions only through groups",
		"1_16.rego": "CIS 1.16: Ensure a support role has been created to manage incidents with AWS Support",
	}

	mitreMappingTable := map[string][]Mitre{
		"1_3.rego": {
			{ID: "T1059.009", Name: "Command and Scripting Interpreter: Cloud API"},
			{ID: "T1098.001", Name: "Account Manipulation: Additional Cloud Credentials"},
		},
		"1_4.rego": {
			{ID: "T1098.003", Name: "Account Manipulation: Additional Cloud Roles"},
			{ID: "T1098.001", Name: "Account Manipulation: Additional Cloud Credentials"},
		},
		"1_6.rego": {
			{ID: "T1548.005", Name: "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access"},
			{ID: "T1651", Name: "Cloud Administration Command"},
			{ID: "T1098.001", Name: "Account Manipulation: Additional Cloud Credentials"},
		},
		"1_7.rego": {
			{ID: "T1098.003", Name: "Account Manipulation: Additional Cloud Roles"},
		},
		"1_8.rego": {
			{ID: "T1098.003", Name: "Account Manipulation: Additional Cloud Roles"},
		},
		"1_9.rego": {
			{ID: "T1098.001", Name: "Account Manipulation: Additional Cloud Credentials"},
			{ID: "T1136.003", Name: "Create Account: Cloud Account"},
		},
		"1_11.rego": {
			{ID: "T1098.003", Name: "Account Manipulation: Additional Cloud Roles"},
			{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts"},
		},
		"1_12.rego": {
			{ID: "T1059.009", Name: "Command and Scripting Interpreter: Cloud API"},
		},
		"1_14.rego": {
			{ID: "T1098.001", Name: "Account Manipulation: Additional Cloud Credentials"},
			{ID: "T1098.003", Name: "Account Manipulation: Additional Cloud Roles"},
		},
		"1_16.rego": {
			{ID: "T1078.004", Name: "Valid Accounts: Cloud Accounts"},
		},
	}

	wg.Add(len(auditFuncs))
	for _, f := range auditFuncs {
		go func(fn func() (string, any, error)) {
			defer wg.Done()
			policy, checker, err := fn()
			if err != nil {
				log.Printf("Error in %s: %v", policy, err)
				return
			}
			if checker != "true" {
				mu.Lock()
				for _, mitre := range mitreMappingTable[policy] {
					results = append(results, CISMITREMapping{
						CISID:   strings.TrimSuffix(policy, ".rego"),
						CISName: cisPolicyInfo[policy],
						MITREID: mitre.ID,
						MITRE:   mitre.Name,
					})
				}
				mu.Unlock()
			}
		}(f)
	}
	wg.Wait()
	file, err := os.Create("violations.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", " ")
	err = enc.Encode(results)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Violations saved to violations.json")

}
