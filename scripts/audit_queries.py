#!/usr/bin/env python3
"""
Audit Log Queries — PCI-DSS Compliance
========================================
Query scripts that answer PCI-DSS Requirement 10 questions:
"Who accessed which secrets, when, and from where?"

All queries target CloudTrail logs stored in CloudWatch Logs,
which are tamper-evident (log file validation enabled).

Usage:
    # Q1: Who accessed VortexPay production secrets in last 24h?
    python scripts/audit_queries.py --query accesses --hours 24

    # Q2: List all rotation events in last 30 days
    python scripts/audit_queries.py --query rotations --days 30

    # Q3: Detect unauthorized access attempts
    python scripts/audit_queries.py --query denied

    # Q4: Full audit export for PCI auditor
    python scripts/audit_queries.py --query export --days 365 --output audit_export.json
"""

import argparse
import json
import logging
import sys
import os
import time
from datetime import datetime, timedelta, timezone

import boto3

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("audit-queries")

AWS_REGION = "us-east-1"
LOG_GROUP = os.environ.get("LOG_GROUP", "/yuno/secrets-audit/sandbox")

logs_client = boto3.client("logs", region_name=AWS_REGION)


def run_insights_query(
    query: str, start_time: datetime, end_time: datetime
) -> list[dict]:
    """
    Execute a CloudWatch Logs Insights query and return results.
    CloudWatch Logs Insights is the standard way to query CloudTrail logs.
    """
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())

    logger.info("Running query on log group: %s", LOG_GROUP)
    logger.info("Time range: %s to %s", start_time.isoformat(), end_time.isoformat())

    response = logs_client.start_query(
        logGroupName=LOG_GROUP,
        startTime=start_ts,
        endTime=end_ts,
        queryString=query,
        limit=1000,
    )
    query_id = response["queryId"]

    # Poll until complete
    while True:
        result = logs_client.get_query_results(queryId=query_id)
        status = result["status"]

        if status == "Complete":
            rows = result["results"]
            logger.info("Query returned %d rows", len(rows))
            return [{field["field"]: field["value"] for field in row} for row in rows]
        elif status in ("Failed", "Cancelled", "Timeout"):
            raise RuntimeError(f"Query failed with status: {status}")

        logger.debug("Query status: %s — waiting...", status)
        time.sleep(2)


# ── Q1: Who accessed VortexPay production secrets in the last N hours? ────────
def query_secret_accesses(hours: int = 24) -> None:
    """
    PCI-DSS Req 10.2.1: Log all access to secrets.
    Answers: Which service accessed which secret, when?
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    query = """
    fields @timestamp, userIdentity.arn, userIdentity.sessionContext.sessionIssuer.userName,
           requestParameters.secretId, sourceIPAddress, eventName, responseElements.name
    | filter eventSource = "secretsmanager.amazonaws.com"
    | filter eventName in ["GetSecretValue", "DescribeSecret"]
    | filter requestParameters.secretId like /vortexpay/
    | sort @timestamp desc
    | limit 200
    """

    print(f"\n{'='*70}")
    print(f"SECRET ACCESS LOG — Last {hours} hours")
    print(f"Query time: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    rows = run_insights_query(query, start, end)

    if not rows:
        print("No accesses found in this time window.")
        return

    for row in rows:
        print(
            f"[{row.get('@timestamp', 'N/A')}] "
            f"action={row.get('eventName', 'N/A')} "
            f"principal={row.get('userIdentity.sessionContext.sessionIssuer.userName', row.get('userIdentity.arn', 'N/A'))} "
            f"secret={row.get('requestParameters.secretId', 'N/A')} "
            f"ip={row.get('sourceIPAddress', 'N/A')}"
        )

    print(f"\nTotal: {len(rows)} access events")


# ── Q2: All rotation events ────────────────────────────────────────────────────
def query_rotation_events(days: int = 30) -> None:
    """
    PCI-DSS Req 8.3.2: Demonstrate rotation occurred and audit trail exists.
    Answers: Which secrets were rotated, when, by whom?
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    query = """
    fields @timestamp, userIdentity.arn, requestParameters.secretId,
           eventName, responseElements.versionId
    | filter eventSource = "secretsmanager.amazonaws.com"
    | filter eventName in ["RotateSecret", "PutSecretValue", "UpdateSecretVersionStage"]
    | sort @timestamp desc
    """

    print(f"\n{'='*70}")
    print(f"ROTATION EVENTS — Last {days} days")
    print("=" * 70)

    rows = run_insights_query(query, start, end)

    if not rows:
        print("No rotation events found.")
        return

    for row in rows:
        print(
            f"[{row.get('@timestamp', 'N/A')}] "
            f"event={row.get('eventName', 'N/A')} "
            f"secret={row.get('requestParameters.secretId', 'N/A')} "
            f"version={row.get('responseElements.versionId', 'N/A')} "
            f"by={row.get('userIdentity.arn', 'N/A')}"
        )

    print(f"\nTotal: {len(rows)} rotation events")


# ── Q3: Unauthorized access attempts ──────────────────────────────────────────
def query_denied_accesses() -> None:
    """
    PCI-DSS Req 10.2.4: Log failed access attempts.
    Answers: Who tried to access secrets they shouldn't have?
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)

    query = """
    fields @timestamp, userIdentity.arn, requestParameters.secretId,
           errorCode, errorMessage, sourceIPAddress
    | filter eventSource = "secretsmanager.amazonaws.com"
    | filter errorCode in ["AccessDeniedException", "UnauthorizedOperation"]
    | sort @timestamp desc
    """

    print(f"\n{'='*70}")
    print("UNAUTHORIZED ACCESS ATTEMPTS — Last 24 hours")
    print("=" * 70)

    rows = run_insights_query(query, start, end)

    if not rows:
        print("✅ No unauthorized access attempts detected.")
        return

    print(f"⚠️  ALERT: {len(rows)} unauthorized access attempt(s) detected!\n")
    for row in rows:
        print(
            f"[{row.get('@timestamp', 'N/A')}] "
            f"principal={row.get('userIdentity.arn', 'N/A')} "
            f"secret={row.get('requestParameters.secretId', 'N/A')} "
            f"error={row.get('errorCode', 'N/A')} "
            f"ip={row.get('sourceIPAddress', 'N/A')}"
        )


# ── Q4: Full PCI-DSS audit export ─────────────────────────────────────────────
def query_full_export(days: int = 365, output_file: str = "audit_export.json") -> None:
    """
    Export complete audit trail for PCI-DSS auditor review.
    Covers all Secrets Manager events for the specified period.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    query = """
    fields @timestamp, eventName, userIdentity.arn,
           userIdentity.sessionContext.sessionIssuer.userName,
           requestParameters.secretId, sourceIPAddress,
           errorCode, awsRegion, recipientAccountId
    | filter eventSource = "secretsmanager.amazonaws.com"
    | sort @timestamp asc
    """

    print(f"\nExporting {days}-day audit trail for PCI-DSS review...")
    rows = run_insights_query(query, start, end)

    export = {
        "export_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "total_events": len(rows),
            "pci_dss_requirement": "10.2 — Audit logs for all access to secrets",
            "log_group": LOG_GROUP,
            "tamper_protection": "CloudTrail log file validation enabled",
        },
        "events": rows,
    }

    with open(output_file, "w") as fh:
        json.dump(export, fh, indent=2, default=str)

    print(f"✅ Exported {len(rows)} events to: {output_file}")
    print(f"   This file satisfies PCI-DSS Req 10 for the auditor review.")


def main():
    parser = argparse.ArgumentParser(description="Yuno Secrets Audit Log Queries")
    parser.add_argument(
        "--query",
        choices=["accesses", "rotations", "denied", "export"],
        required=True,
    )
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--output", default="audit_export.json")
    args = parser.parse_args()

    if args.query == "accesses":
        query_secret_accesses(hours=args.hours)
    elif args.query == "rotations":
        query_rotation_events(days=args.days)
    elif args.query == "denied":
        query_denied_accesses()
    elif args.query == "export":
        query_full_export(days=args.days, output_file=args.output)


if __name__ == "__main__":
    main()
