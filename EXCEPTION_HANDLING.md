# Expense Tracker - Exception Handling Documentation

## Overview

This document outlines the comprehensive exception handling system implemented in the expense tracker application. The system provides robust error handling across all components to ensure reliability and user-friendly error reporting.

## Exception Handling Architecture

### 1. Custom Exception Classes

#### Base Exceptions
```python
class ExpenseTrackerError(Exception)
    """Base exception for expense tracker errors"""

class FileProcessingError(ExpenseTrackerError)
    """Error during file processing"""

class DatabaseError(ExpenseTrackerError)
    """Database operation error"""

class AuthenticationError(ExpenseTrackerError)
    """Authentication related error"""
```

#### Module-Specific Exceptions

**Extractor Module (`extractor.py`)**
```python
class FileExtractionError(Exception)
    """Base exception for file extraction errors"""

class OCRError(FileExtractionError)
    """OCR processing error"""

class PDFError(FileExtractionError)
    """PDF processing error"""
```

**Parser Module (`parser.py`)**
```python
class ParsingError(Exception)
    """Base exception for parsing errors"""

class TransactionParsingError(ParsingError)
    """Error parsing transaction data"""

class AggregationError(ParsingError)
    """Error aggregating transaction data"""
```

### 2. Logging System

#### Configuration
- **Log Level**: INFO
- **Log Format**: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`
- **Handlers**: 
  - File: `expense_tracker.log`
  - Console: Standard output

#### Log Categories
- **INFO**: Normal operations, user actions
- **WARNING**: Non-critical issues, failed login attempts
- **ERROR**: Application errors, database issues
- **CRITICAL**: System failures (not currently used)

### 3. Database Exception Handling

#### Safe Database Operations
```python
def safe_db_operation(operation, *args, **kwargs):
    """Execute database operation with proper error handling"""
```

**Features:**
- Automatic session management
- Transaction rollback on errors
- Comprehensive error logging
- Custom exception translation

**Handled Exceptions:**
- `IntegrityError`: Data integrity violations
- `SQLAlchemyError`: General database errors
- `Exception`: Unexpected errors

### 4. File Processing Exception Handling

#### Image Processing (`extract_text_from_image`)
**Handled Errors:**
- File not found
- Empty files
- Invalid image formats
- Tesseract OCR not found
- OCR processing errors
- Permission denied
- Corrupted images

#### PDF Processing (`extract_text_from_pdf`)
**Handled Errors:**
- File not found
- Empty files
- Corrupted PDFs
- Permission denied
- Page extraction errors
- Invalid PDF format

#### File Validation
```python
def validate_file_for_processing(file_path: str) -> tuple[bool, str]:
    """Validate if a file can be processed safely."""
```

**Validation Checks:**
- File existence
- File size (0 bytes, max 50MB)
- File type (PNG, JPG, JPEG, PDF)
- File permissions

### 5. Transaction Processing Exception Handling

#### Text Parsing (`parse_transactions`)
**Handled Errors:**
- Empty input text
- Invalid input types
- Malformed transaction lines
- Invalid amount formats
- Missing descriptions

**Features:**
- Line-by-line error handling
- Detailed logging of parsing issues
- Graceful degradation (skip invalid lines)

#### Data Aggregation (`aggregate_transactions`)
**Handled Errors:**
- Invalid transaction dictionaries
- Missing required fields
- Invalid data types
- Amount conversion errors

### 6. Web Application Exception Handling

#### Global Error Handlers
```python
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    """Handle file size limit errors"""

@app.errorhandler(BadRequest)
def bad_request(error):
    """Handle bad request errors"""
```

#### Route-Specific Error Handling

**Authentication Routes:**
- Input validation (empty username/password)
- Database connection errors
- User existence checks
- Password hashing errors

**File Upload Route:**
- File validation
- Text extraction errors
- Transaction parsing errors
- Database persistence errors
- Threshold checking errors

**Data Retrieval Routes:**
- Database query errors
- Data formatting errors
- Export generation errors

### 7. User Experience Features

#### Flash Message System
- **Success**: Green messages for successful operations
- **Error**: Red messages for error conditions
- **Warning**: Yellow messages for warnings

#### Error Recovery
- Graceful fallbacks when possible
- Detailed error messages for users
- Automatic redirects to safe pages
- Partial success handling (some files processed successfully)

### 8. Security Considerations

#### Input Validation
- Filename sanitization using `secure_filename()`
- File size limits (50MB)
- File type restrictions
- SQL injection prevention via ORM

#### Error Information Disclosure
- Generic error messages for users
- Detailed logging for administrators
- No sensitive data in error responses

## Error Handling Examples

### Example 1: File Upload with Multiple Errors
```python
# User uploads 3 files: valid.pdf, corrupt.pdf, image.png
# Result: 
# - valid.pdf: Successfully processed
# - corrupt.pdf: Error logged, user notified, processing continues
# - image.png: Successfully processed
# User sees: "Error extracting text from corrupt.pdf" + successful results
```

### Example 2: Database Connection Loss
```python
# Database becomes unavailable during operation
# Result:
# - Error logged with full traceback
# - User sees: "Database operation failed"
# - User redirected to safe page
# - No data corruption (transaction rollback)
```

### Example 3: Invalid Transaction Data
```python
# OCR produces malformed text
# Result:
# - Invalid lines skipped with warnings
# - Valid transactions still processed
# - User sees summary of successful parsing
# - Detailed logs for debugging
```

## Monitoring and Debugging

### Log Analysis
- Check `expense_tracker.log` for detailed error information
- Monitor error frequency and patterns
- Track user experience issues

### Error Metrics
- Database operation success rate
- File processing success rate
- OCR accuracy issues
- User authentication problems

### Troubleshooting Guide

#### Common Issues:
1. **Tesseract OCR not found**: Check installation path in `extractor.py`
2. **Database locked**: Multiple concurrent access issues
3. **File permission errors**: Check upload directory permissions
4. **Memory issues**: Large file processing problems

## Best Practices

1. **Always use `safe_db_operation()`** for database operations
2. **Log all errors** with appropriate detail level
3. **Provide user-friendly messages** while logging technical details
4. **Validate inputs** before processing
5. **Handle partial failures** gracefully
6. **Use appropriate HTTP status codes**
7. **Clean up resources** in finally blocks

## Future Improvements

1. **Retry mechanisms** for transient failures
2. **Circuit breaker pattern** for external services
3. **Rate limiting** for user uploads
4. **Enhanced monitoring** with metrics collection
5. **Automated error alerting** for critical failures
6. **User notification system** for processing status 