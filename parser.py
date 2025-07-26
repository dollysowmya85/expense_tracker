import re
import logging
from collections import defaultdict
from typing import List, Dict

# Configure logging
logger = logging.getLogger(__name__)

# Only lines that begin with MM/DD or MM/DD/YYYY
DATE_RE   = re.compile(r'^\d{2}/\d{2}(?:/\d{2,4})')
AMOUNT_RE = re.compile(r'(-?\$?[\d,]+\.\d{2})')

class ParsingError(Exception):
    """Base exception for parsing errors"""
    pass

class TransactionParsingError(ParsingError):
    """Error parsing transaction data"""
    pass

class AggregationError(ParsingError):
    """Error aggregating transaction data"""
    pass

def parse_transactions(text: str) -> List[Dict[str, float]]:
    """
    Given OCR/pdf‑extracted text from a statement, only capture lines
    that start with a date (MM/DD or MM/DD/YYYY) followed by description
    and an amount.
    """
    if not text:
        logger.warning("Empty text provided for transaction parsing")
        return []
    
    if not isinstance(text, str):
        logger.error(f"Invalid input type for parsing: {type(text)}")
        raise TransactionParsingError("Input must be a string")
    
    txs = []
    lines_processed = 0
    lines_parsed = 0
    
    try:
        logger.info(f"Starting transaction parsing for text of length {len(text)}")
        
        for line_num, raw in enumerate(text.splitlines(), 1):
            lines_processed += 1
            line = raw.strip()
            
            if not line or not DATE_RE.match(line):
                continue

            try:
                # Split out the amount
                parts = AMOUNT_RE.split(line)
                if len(parts) >= 3:
                    # parts = [before_amt, amt, after_amt]
                    # before_amt = "MM/DD Description…"
                    before_amt = parts[0].strip()
                    
                    # drop the date from the front
                    # e.g. "07/22/2025  Coffee Shop" → ["07/22/2025", "Coffee Shop"]
                    if ' ' in before_amt:
                        desc = before_amt.split(None, 1)[1]
                    else:
                        desc = "Unknown"
                        logger.warning(f"No description found on line {line_num}: {line}")
                    
                    # Parse amount
                    amount_str = parts[1].replace('$','').replace(',','')
                    try:
                        amt = float(amount_str)
                        if amt == 0:
                            logger.warning(f"Zero amount found on line {line_num}: {line}")
                        txs.append({"description": desc, "amount": amt})
                        lines_parsed += 1
                        
                    except ValueError as e:
                        logger.warning(f"Invalid amount '{amount_str}' on line {line_num}: {line}")
                        continue
                        
            except Exception as e:
                logger.warning(f"Error parsing line {line_num} '{line}': {str(e)}")
                continue
        
        logger.info(f"Transaction parsing completed. Processed {lines_processed} lines, parsed {lines_parsed} transactions")
        return txs
        
    except Exception as e:
        error_msg = f"Unexpected error during transaction parsing: {str(e)}"
        logger.error(error_msg)
        raise TransactionParsingError(error_msg) from e

def aggregate_transactions(transactions: List[Dict[str, float]]) -> Dict[str, float]:
    """
    Sum transaction amounts by description with error handling.
    """
    if not transactions:
        logger.info("No transactions to aggregate")
        return {}
    
    if not isinstance(transactions, list):
        logger.error(f"Invalid input type for aggregation: {type(transactions)}")
        raise AggregationError("Transactions must be a list")
    
    try:
        logger.info(f"Starting aggregation of {len(transactions)} transactions")
        totals: Dict[str, float] = defaultdict(float)
        processed_count = 0
        error_count = 0
        
        for i, tx in enumerate(transactions):
            try:
                if not isinstance(tx, dict):
                    logger.warning(f"Transaction {i} is not a dictionary: {type(tx)}")
                    error_count += 1
                    continue
                
                if "description" not in tx or "amount" not in tx:
                    logger.warning(f"Transaction {i} missing required fields: {tx}")
                    error_count += 1
                    continue
                
                desc = tx["description"]
                amount = tx["amount"]
                
                if not isinstance(desc, str):
                    logger.warning(f"Transaction {i} has invalid description type: {type(desc)}")
                    desc = str(desc)
                
                if not isinstance(amount, (int, float)):
                    logger.warning(f"Transaction {i} has invalid amount type: {type(amount)}")
                    try:
                        amount = float(amount)
                    except (ValueError, TypeError):
                        logger.error(f"Cannot convert amount to float for transaction {i}: {amount}")
                        error_count += 1
                        continue
                
                totals[desc] += amount
                processed_count += 1
                
            except Exception as e:
                logger.error(f"Error processing transaction {i}: {str(e)}")
                error_count += 1
                continue
        
        result = dict(totals)
        logger.info(f"Aggregation completed. Processed {processed_count}/{len(transactions)} transactions successfully, {error_count} errors")
        
        if error_count > 0:
            logger.warning(f"Aggregation had {error_count} errors out of {len(transactions)} transactions")
        
        return result
        
    except Exception as e:
        error_msg = f"Unexpected error during transaction aggregation: {str(e)}"
        logger.error(error_msg)
        raise AggregationError(error_msg) from e

def validate_transaction_data(transaction: Dict) -> tuple[bool, str]:
    """Validate a single transaction dictionary."""
    try:
        if not isinstance(transaction, dict):
            return False, f"Transaction must be a dictionary, got {type(transaction)}"
        
        required_fields = ["description", "amount"]
        for field in required_fields:
            if field not in transaction:
                return False, f"Missing required field: {field}"
        
        desc = transaction["description"]
        if not isinstance(desc, str) or not desc.strip():
            return False, "Description must be a non-empty string"
        
        amount = transaction["amount"]
        if not isinstance(amount, (int, float)):
            try:
                float(amount)
            except (ValueError, TypeError):
                return False, f"Amount must be a number, got {type(amount)}"
        
        return True, "Transaction is valid"
    
    except Exception as e:
        return False, f"Error validating transaction: {str(e)}"

if __name__ == '__main__':
    # smoke‑test with error handling
    try:
        sample = """
        07/01/2025 Office Supplies       $45.00
        07/15/2025 Software License      $150.00
        07/20/2025 Coffee Shop           $8.50
        Invalid line without date
        07/25/2025 Invalid Amount        $invalid
        07/30/2025                       $25.00
        """
        
        print("Testing transaction parsing...")
        parsed = parse_transactions(sample)
        print("Parsed transactions:", parsed)
        
        print("\nTesting aggregation...")
        aggregated = aggregate_transactions(parsed)
        print("Aggregated:", aggregated)
        
        # Test error cases
        print("\nTesting error cases...")
        
        # Empty input
        empty_result = parse_transactions("")
        print("Empty input result:", empty_result)
        
        # Invalid transaction for aggregation
        invalid_txs = [
            {"description": "Valid", "amount": 10.0},
            {"description": "Invalid", "amount": "not_a_number"},
            {"invalid": "structure"},
            {"description": "", "amount": 5.0}  # Empty description
        ]
        
        try:
            invalid_aggregated = aggregate_transactions(invalid_txs)
            print("Aggregation with invalid data:", invalid_aggregated)
        except AggregationError as e:
            print(f"Aggregation error (expected): {e}")
            
    except (TransactionParsingError, AggregationError) as e:
        print(f"Parsing/Aggregation error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


