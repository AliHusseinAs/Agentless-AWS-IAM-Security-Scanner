package aws.iam.scanner.cis._1_3.benchmark 

default compliant = false 

compliant {
input.AccountAccessKeysPresent == 0
}
