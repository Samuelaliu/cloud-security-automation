import boto3
import json
from datetime import datetime

def generate_compliance_report():
    """
    Generates a compliance report showing which AWS resources
    are compliant and which are not, based on AWS Config rules.
    """

    config_client = boto3.client('config', region_name='us-east-1')

    print("\n" + "=" * 60)
    print("       AWS SECURITY COMPLIANCE REPORT")
    print(f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Get all config rules and their compliance status
    rules_response = config_client.describe_config_rules()
    rules = rules_response['ConfigRules']

    total_compliant     = 0
    total_non_compliant = 0

    for rule in rules:
        rule_name = rule['ConfigRuleName']

        compliance_response = config_client.get_compliance_details_by_config_rule(
            ConfigRuleName=rule_name,
            ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT']
        )

        results = compliance_response['EvaluationResults']
        compliant     = [r for r in results if r['ComplianceType'] == 'COMPLIANT']
        non_compliant = [r for r in results if r['ComplianceType'] == 'NON_COMPLIANT']

        total_compliant     += len(compliant)
        total_non_compliant += len(non_compliant)

        status = "✅ PASS" if len(non_compliant) == 0 else "❌ FAIL"

        print(f"\nRule: {rule_name}")
        print(f"Status: {status}")
        print(f"  Compliant resources:     {len(compliant)}")
        print(f"  Non-compliant resources: {len(non_compliant)}")

        if non_compliant:
            print("  Non-compliant resources:")
            for r in non_compliant:
                resource_id = r['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                print(f"    - {resource_id}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total Compliant Resources:     {total_compliant}")
    print(f"Total Non-Compliant Resources: {total_non_compliant}")

    total = total_compliant + total_non_compliant
    if total > 0:
        score = (total_compliant / total) * 100
        print(f"Compliance Score:              {score:.1f}%")

    print("=" * 60)

    # Save report to file
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_compliant": total_compliant,
        "total_non_compliant": total_non_compliant,
        "compliance_score": score if total > 0 else 0
    }

    with open('reports/compliance_report.json', 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to reports/compliance_report.json")

if __name__ == "__main__":
    generate_compliance_report()