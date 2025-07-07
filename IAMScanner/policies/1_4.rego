package aws.iam.scanner.cis._1_4.benchmark.compliant 

default compliant = false
compliant {
  input.AccountMFAEnabled == 1
}

compliant {
  input.AccountPasswordPresent == 0
}
