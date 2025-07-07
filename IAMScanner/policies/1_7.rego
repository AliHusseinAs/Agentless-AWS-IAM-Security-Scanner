package aws.iam.scanner.cis._1_7.benchmark.compliant 

default compliant = false


compliant {
input.MinimumPasswordLength >= 14
}
