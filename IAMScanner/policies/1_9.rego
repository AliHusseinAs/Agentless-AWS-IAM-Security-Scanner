package aws.iam.scanner.cis._1_9.benchmark.compliant


default compliant = false 

compliant {
    input.MfaEnabled == 0
}
