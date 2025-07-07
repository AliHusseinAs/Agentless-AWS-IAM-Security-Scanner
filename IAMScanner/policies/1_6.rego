package aws.iam.scanner.cis._1_6.benchmark.compliant


default compliant = false


compliant {
  input.DaysUsed > 30
}