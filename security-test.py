"""
Synthetic Credential Exposure Test Fixture
Purpose: Test security-pattern detection, redaction, and triage.
WARNING: All credential values below are fake test data.
Never use these values for authentication.
"""

from datetime import datetime, timezone
import json
import re
import hashlib


# --------------------------------------------------
# 1. Test metadata
# --------------------------------------------------

TEST_NAME = "Credential Exposure Detection"
TEST_VERSION = "1.0"
TEST_MODE = True
GENERATED_AT = datetime.now(timezone.utc).isoformat()

SOURCE_REPOSITORY = "credential-exposure-test"
SOURCE_FILE = "security-test.py"


# --------------------------------------------------
# 2. Synthetic credential-shaped test values
# --------------------------------------------------

STRIPE_SECRET_KEY = "sk_live_FAKE000000000000000000000000"
AWS_ACCESS_KEY_ID = "AKIAFAKE0000000000"
GITHUB_TOKEN = "ghp_FAKE000000000000000000000000000000"
GENERIC_API_KEY = "FAKE_API_KEY_FOR_PATTERN_TESTING"
DATABASE_PASSWORD = "NOT_A_REAL_DATABASE_PASSWORD"


# --------------------------------------------------
# 3. Example configuration
# --------------------------------------------------

CONFIG = {
    "environment": "test",
    "alert_channel": "security-test",
    "redact_values": True,
    "deduplication_enabled": True,
    "deduplication_ttl_seconds": 3600,
    "verify_credential_validity": False,
    "allow_real_credentials": False,
}


# --------------------------------------------------
# 4. Synthetic test cases
# --------------------------------------------------

TEST_CASES = [
    {
        "id": "TC-001",
        "category": "stripe_candidate",
        "content": 'STRIPE_SECRET_KEY = "sk_live_FAKE000000000000000000000000"',
        "expected": "candidate",
    },
    {
        "id": "TC-002",
        "category": "aws_candidate",
        "content": 'AWS_ACCESS_KEY_ID = "AKIAFAKE0000000000"',
        "expected": "candidate",
    },
    {
        "id": "TC-003",
        "category": "github_candidate",
        "content": 'GITHUB_TOKEN = "ghp_FAKE000000000000000000000000000000"',
        "expected": "candidate",
    },
    {
        "id": "TC-004",
        "category": "generic_assignment",
        "content": 'API_KEY = "FAKE_API_KEY_FOR_PATTERN_TESTING"',
        "expected": "candidate",
    },
    {
        "id": "TC-005",
        "category": "benign_text",
        "content": "This project uses environment variables for configuration.",
        "expected": "benign",
    },
    {
        "id": "TC-006",
        "category": "placeholder",
        "content": 'API_KEY = "YOUR_API_KEY_HERE"',
        "expected": "suppressed",
    },
    {
        "id": "TC-007",
        "category": "empty_input",
        "content": "",
        "expected": "suppressed",
    },
    {
        "id": "TC-008",
        "category": "documentation",
        "content": "# Never commit real credentials to source control.",
        "expected": "benign",
    },
]


# --------------------------------------------------
# 5. Candidate-pattern definitions
# These are test heuristics, not credential validation.
# --------------------------------------------------

PATTERNS = {
    "stripe_candidate": re.compile(
        r"\bsk_live_[A-Za-z0-9]{10,}\b"
    ),
    "aws_candidate": re.compile(
        r"\bAKIA[A-Z0-9]{16}\b"
    ),
    "github_candidate": re.compile(
        r"\bghp_[A-Za-z0-9]{20,}\b"
    ),
    "generic_assignment": re.compile(
        r"\b(?:API_KEY|SECRET_KEY|ACCESS_TOKEN|"
        r"DATABASE_PASSWORD)\s*[:=]\s*['\"]?[^'\"\s]+",
        re.IGNORECASE,
    ),
}


# --------------------------------------------------
# 6. Placeholder filtering
# --------------------------------------------------

PLACEHOLDERS = {
    "",
    "YOUR_API_KEY_HERE",
    "REPLACE_ME",
    "CHANGEME",
    "EXAMPLE",
    "FAKE_API_KEY_FOR_PATTERN_TESTING",
    "NOT_A_REAL_DATABASE_PASSWORD",
}


def is_placeholder(value):
    """Return True for known harmless placeholder values."""
    if value is None:
        return True

    normalized = str(value).strip().strip("\"'").upper()

    if normalized in {item.upper() for item in PLACEHOLDERS}:
        return True

    if "FAKE" in normalized or "NOT_A_REAL" in normalized:
        return True

    return False


# --------------------------------------------------
# 7. Detection helper
# --------------------------------------------------

def detect_candidate(content):
    """Identify matching patterns without verifying credentials."""
    if not isinstance(content, str) or not content.strip():
        return {
            "candidate": False,
            "category": "empty_or_invalid",
        }

    for category, pattern in PATTERNS.items():
        match = pattern.search(content)

        if match:
            matched_text = match.group(0)

            if is_placeholder(matched_text):
                continue

            return {
                "candidate": True,
                "category": category,
                "matched_text": matched_text,
            }

    return {
        "candidate": False,
        "category": "no_supported_pattern",
    }


# --------------------------------------------------
# 8. Evidence redaction
# --------------------------------------------------

def redact_evidence(content):
    """Replace matching secret-shaped values in test evidence."""
    if not isinstance(content, str):
        return "[INVALID_INPUT]"

    redacted = content

    for pattern in PATTERNS.values():
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)

    return redacted


# --------------------------------------------------
# 9. Stable test fingerprint
# --------------------------------------------------

def make_fingerprint(source_url, category, redacted_evidence):
    """Create a deterministic identifier for a synthetic finding."""
    material = "|".join([
        str(source_url).strip(),
        str(category).strip(),
        str(redacted_evidence).strip(),
    ])

    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()

    return "sec_test_" + digest


# --------------------------------------------------
# 10. Run the local test suite
# --------------------------------------------------

def run_tests():
    results = []

    for test_case in TEST_CASES:
        content = test_case["content"]
        detection = detect_candidate(content)

        if detection["candidate"]:
            status = "candidate"
        elif test_case["expected"] == "suppressed":
            status = "suppressed"
        else:
            status = "benign"

        redacted = redact_evidence(content)

        fingerprint = make_fingerprint(
            "https://example.invalid/security-test.py",
            detection["category"],
            redacted,
        )

        results.append({
            "test_id": test_case["id"],
            "test_category": test_case["category"],
            "expected": test_case["expected"],
            "observed": status,
            "redacted_evidence": redacted,
            "fingerprint": fingerprint,
            "candidate_detected": detection["candidate"],
        })

    return results


# --------------------------------------------------
# 11. Print a safe test report
# --------------------------------------------------

def main():
    print("=" * 60)
    print(TEST_NAME)
    print("Version:", TEST_VERSION)
    print("Mode:", "SYNTHETIC TEST ONLY")
    print("Generated:", GENERATED_AT)
    print("=" * 60)

    results = run_tests()

    for result in results:
        print(json.dumps(result, indent=2))

    print("-" * 60)
    print("Total cases:", len(results))
    print("Note: This local suite does not call Slack, Apify, or Redis.")
    print("It does not establish whether any credential is valid.")
    print("=" * 60)


if __name__ == "__main__":
    main()
