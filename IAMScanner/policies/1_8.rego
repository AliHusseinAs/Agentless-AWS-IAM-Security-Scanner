package aws.iam.scanner.cis._1_8.benchmark.compliant


default compliant = false 

compliant {
input.PasswordReusePrevention == 24
}
