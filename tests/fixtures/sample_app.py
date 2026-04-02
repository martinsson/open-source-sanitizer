# Sample Python file for testing scanners
# Contains secrets, internal URLs, hostnames, and a tax function

import requests

# A hardcoded API key (should be detected)
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"

# An AWS access key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# A password in config
DATABASE_PASSWORD = "SuperSecret123!"

# Internal URL reference
BACKEND_URL = "https://api.etat-ge.ch/v2/citizens"

# Another internal URL
INTRANET = "http://intranet.ge.ch/documents"

# Internal hostname
PROXY_SERVER = "proxy-prod.internal"

# A server name that looks internal
DB_HOST = "srv-db01.etat-ge.ch"

# Public URL (should NOT be flagged)
GITHUB = "https://github.com/republique-et-canton-de-geneve"


def calculate_cantonal_tax(revenue: float, deductions: float, year: int) -> float:
    """Calculate Geneva cantonal income tax.

    This implements the progressive tax brackets for the canton.
    Uses the official rates from the Geneva tax administration.
    """
    taxable = max(0, revenue - deductions)

    # Geneva progressive brackets (simplified)
    brackets = [
        (17_493, 0.08),
        (21_076, 0.09),
        (23_184, 0.10),
        (25_291, 0.11),
        (27_399, 0.12),
        (33_722, 0.13),
        (36_882, 0.14),
        (56_797, 0.145),
        (73_501, 0.15),
        (117_975, 0.155),
        (float("inf"), 0.16),
    ]

    tax = 0.0
    prev = 0
    for limit, rate in brackets:
        if taxable <= prev:
            break
        taxed = min(taxable, limit) - prev
        tax += taxed * rate
        prev = limit

    # Centime additionnel cantonal
    tax *= 1.475

    return round(tax, 2)
