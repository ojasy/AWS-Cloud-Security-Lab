import boto3
import csv
import glob
import sys
from datetime import datetime, timezone

sh      = boto3.client("securityhub", region_name="ca-central-1")
sts     = boto3.client("sts")
ACCOUNT = sts.get_caller_identity()["Account"]
REGION  = "ca-central-1"

def csv_to_asff(row):
    now = datetime.now(timezone.utc).isoformat()
    return {
        "SchemaVersion": "2018-10-08",
        "Id":            f"cloudtrail-{row['timestamp']}-{row['event']}",
        "ProductArn":    (f"arn:aws:securityhub:{REGION}:{ACCOUNT}"
                          f":product/{ACCOUNT}/default"),
        "GeneratorId":   "cloudtrail-analyzer",
        "AwsAccountId":  ACCOUNT,
        "Types":         ["Software and Configuration Checks"],
        "CreatedAt":     now,
        "UpdatedAt":     now,
        "Severity":      {"Label": row["severity"]},
        "Title":         f"CloudTrail: {row['event']} detected",
        "Description":   (f"Category: {row['category']} | "
                          f"MITRE: {row['mitre']} | "
                          f"User: {row['user']} | "
                          f"IP: {row['source_ip']}"),
        "Resources": [{
            "Type": "AwsIamUser",
            "Id":   row.get("user", "unknown")
        }]
    }

def import_alerts(csv_file):
    print(f"[*] Importing from {csv_file}")
    findings = []
    with open(csv_file) as f:
        for row in csv.DictReader(f):
            findings.append(csv_to_asff(row))

    imported = 0
    for i in range(0, len(findings), 100):
        batch = findings[i:i+100]
        resp  = sh.batch_import_findings(Findings=batch)
        imported += resp["SuccessCount"]
        print(f"  Batch {i//100 + 1}: "
              f"{resp['SuccessCount']} imported, "
              f"{resp['FailedCount']} failed")

    print(f"\n[✓] Total imported: {imported}/{len(findings)}")

if __name__ == "__main__":
    csvs = glob.glob("alerts_*.csv")
    if not csvs:
        print("No alerts CSV found. Run cloudtrail_analyzer.py first.")
        sys.exit(1)
    import_alerts(sorted(csvs)[-1])