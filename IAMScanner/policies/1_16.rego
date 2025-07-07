package aws.iam.scanner.cis._1_16.benchmark.compliant

default compliant = false 

compliant {
    input.policyRoles == 0
}