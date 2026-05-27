import boto3
import json
import gzip
import csv
from datetime import datetime

# ── CONFIG ───────────────────────────────────────────────
BUCKET_NAME = "security-lab-cloudtrail-ojasy"  # <-- change this
REGION      = "ca-central-1"
OUTPUT_CSV  = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# ── DETECTION RULES (MITRE ATT&CK mapped) ────────────────
RULES = {
    "ANTI_FORENSICS": {
        "events":   ["StopLogging", "DeleteTrail", "UpdateTrail"],
        "severity": "CRITICAL",
        "mitre":    "T1562.008"
    },
    "IAM_ESCALATION": {
        "events":   ["CreateUser", "AttachUserPolicy", "CreateAccessKey",
                     "DeactivateMFADevice", "CreateLoginProfile"],
        "severity": "HIGH",
        "mitre":    "T1098"
    },
    "NETWORK_EXPOSURE": {
        "events":   ["AuthorizeSecurityGroupIngress"],
        "severity": "HIGH",
        "mitre":    "T1190"
    },
    "RESOURCE_ABUSE": {
        "events":   ["RunInstances"],
        "severity": "MEDIUM",
        "mitre":    "T1496"
    },
    "RECON": {
        "events":   ["ListBuckets", "DescribeInstances", "ListUsers"],
        "severity": "MEDIUM",
        "mitre":    "T1580"
    },
}

def classify_event(event_name):
    for category, rule in RULES.items():
        if event_name in rule["events"]:
            return category, rule["severity"], rule["mitre"]
    return None, None, None

def analyze_logs():
    s3        = boto3.client("s3", region_name=REGION)
    alerts    = []
    log_count = 0

    print(f"[*] Scanning bucket: {BUCKET_NAME}")
    paginator = s3.get_paginator("list_objects_v2")

    for page in paginator.paginate(Bucket=BUCKET_NAME):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json.gz"):
                continue

            log_count += 1
            body    = s3.get_object(Bucket=BUCKET_NAME, Key=key)["Body"].read()
            records = json.loads(gzip.decompress(body)).get("Records", [])

            for r in records:
                event_name            = r.get("eventName", "")
                category, severity, mitre = classify_event(event_name)

                if category:
                    alerts.append({
                        "timestamp":  r.get("eventTime"),
                        "event":      event_name,
                        "severity":   severity,
                        "category":   category,
                        "mitre":      mitre,
                        "user":       r.get("userIdentity", {}).get("arn", "unknown"),
                        "source_ip":  r.get("sourceIPAddress", "unknown"),
                        "region":     r.get("awsRegion", "unknown"),
                    })

    print(f"\n[+] Scanned {log_count} log files")
    print(f"[!] Detected {len(alerts)} suspicious events\n")

    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        count = sum(1 for a in alerts if a["severity"] == sev)
        if count:
            print(f"    {sev}: {count}")

    if alerts:
        with open(OUTPUT_CSV, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
        print(f"\n[+] Alerts exported → {OUTPUT_CSV}")

if __name__ == "__main__":
    analyze_logs()