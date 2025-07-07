package aws.iam.scanner.cis._1_11.benchmark.compliant


default compliant = false 

compliant {
    input.LastUsed < 45 
}