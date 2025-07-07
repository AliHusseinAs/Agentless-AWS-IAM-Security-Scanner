package aws.iam.scanner.cis._1_12.benchmark.compliant

default compliant = false 

compliant {
    input.activeKey <= 1
}