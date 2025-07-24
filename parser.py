import re
from collections import defaultdict
from typing import List, Dict

# Only lines that begin with MM/DD or MM/DD/YYYY
DATE_RE   = re.compile(r'^\d{2}/\d{2}(?:/\d{2,4})')
AMOUNT_RE = re.compile(r'(-?\$?[\d,]+\.\d{2})')

def parse_transactions(text: str) -> List[Dict[str, float]]:
    """
    Given OCR/pdf‑extracted text from a statement, only capture lines
    that start with a date (MM/DD or MM/DD/YYYY) followed by description
    and an amount.
    """
    txs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or not DATE_RE.match(line):
            continue

        # Split out the amount
        parts = AMOUNT_RE.split(line)
        if len(parts) >= 3:
            # parts = [before_amt, amt, after_amt]
            # before_amt = "MM/DD Description…"
            before_amt = parts[0].strip()
            # drop the date from the front
            # e.g. "07/22/2025  Coffee Shop" → ["07/22/2025", "Coffee Shop"]
            desc = before_amt.split(None, 1)[1] if ' ' in before_amt else "Unknown"
            amt = float(parts[1].replace('$','').replace(',',''))
            txs.append({"description": desc, "amount": amt})
    return txs

def aggregate_transactions(transactions: List[Dict[str, float]]) -> Dict[str, float]:
    """
    Sum transaction amounts by description.
    """
    totals: Dict[str, float] = defaultdict(float)
    for tx in transactions:
        totals[tx["description"]] += tx["amount"]
    return dict(totals)

if __name__ == '__main__':
    # smoke‑test
    sample = """
    07/01/2025 Office Supplies       $45.00
    07/15/2025 Software License      $150.00
    07/20/2025 Coffee Shop           $8.50
    """
    parsed = parse_transactions(sample)
    print("Parsed:", parsed)
    print("Aggregated:", aggregate_transactions(parsed))


