package aws.iam.scanner.cis._1_14.benchmark.compliant

default compliant = false

compliant {
    input.Result == 0
}

