import os
import logging
import pytesseract
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
from PyPDF2.errors import PdfReadError

# Configure logging
logger = logging.getLogger(__name__)

# ← point to your tesseract.exe install location
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

class FileExtractionError(Exception):
    """Base exception for file extraction errors"""
    pass

class OCRError(FileExtractionError):
    """OCR processing error"""
    pass

class PDFError(FileExtractionError):
    """PDF processing error"""
    pass

def extract_text_from_image(path: str) -> str:
    """Run OCR on an image file with error handling."""
    try:
        if not os.path.exists(path):
            raise FileExtractionError(f"Image file not found: {path}")
        
        if not os.path.getsize(path) > 0:
            raise FileExtractionError(f"Image file is empty: {path}")
        
        logger.info(f"Starting OCR extraction for image: {path}")
        img = Image.open(path)
        
        # Validate image
        img.verify()
        img = Image.open(path)  # Reopen after verify
        
        if img.mode not in ('RGB', 'L', 'RGBA'):
            logger.info(f"Converting image mode from {img.mode} to RGB")
            img = img.convert('RGB')
        
        text = pytesseract.image_to_string(img)
        logger.info(f"OCR extraction completed for: {path}")
        
        if not text.strip():
            logger.warning(f"No text extracted from image: {path}")
            return "No text found in image"
        
        return text
        
    except UnidentifiedImageError as e:
        error_msg = f"Cannot identify image file: {path}"
        logger.error(error_msg)
        raise OCRError(error_msg) from e
    
    except pytesseract.TesseractNotFoundError as e:
        error_msg = "Tesseract OCR not found. Please install Tesseract OCR."
        logger.error(error_msg)
        raise OCRError(error_msg) from e
    
    except pytesseract.TesseractError as e:
        error_msg = f"Tesseract OCR error for {path}: {str(e)}"
        logger.error(error_msg)
        raise OCRError(error_msg) from e
    
    except PermissionError as e:
        error_msg = f"Permission denied accessing image file: {path}"
        logger.error(error_msg)
        raise FileExtractionError(error_msg) from e
    
    except Exception as e:
        error_msg = f"Unexpected error processing image {path}: {str(e)}"
        logger.error(error_msg)
        raise OCRError(error_msg) from e

def extract_text_from_pdf(path: str) -> str:
    """Extract all text from a PDF file with error handling."""
    try:
        if not os.path.exists(path):
            raise FileExtractionError(f"PDF file not found: {path}")
        
        if not os.path.getsize(path) > 0:
            raise FileExtractionError(f"PDF file is empty: {path}")
        
        logger.info(f"Starting PDF text extraction for: {path}")
        
        with open(path, 'rb') as file:
            reader = PdfReader(file)
            
            if len(reader.pages) == 0:
                logger.warning(f"PDF has no pages: {path}")
                return "PDF contains no pages"
            
            full_text = []
            pages_processed = 0
            
            for page_num, page in enumerate(reader.pages):
                try:
                    text = page.extract_text()
                    if text and text.strip():
                        full_text.append(text)
                        pages_processed += 1
                except Exception as e:
                    logger.warning(f"Error extracting text from page {page_num + 1} in {path}: {str(e)}")
                    continue
            
            logger.info(f"PDF extraction completed for: {path}. Processed {pages_processed}/{len(reader.pages)} pages")
            
            if not full_text:
                logger.warning(f"No text extracted from PDF: {path}")
                return "No text found in PDF"
            
            return "\n".join(full_text)
    
    except PdfReadError as e:
        error_msg = f"Cannot read PDF file {path}: {str(e)}"
        logger.error(error_msg)
        raise PDFError(error_msg) from e
    
    except PermissionError as e:
        error_msg = f"Permission denied accessing PDF file: {path}"
        logger.error(error_msg)
        raise FileExtractionError(error_msg) from e
    
    except Exception as e:
        error_msg = f"Unexpected error processing PDF {path}: {str(e)}"
        logger.error(error_msg)
        raise PDFError(error_msg) from e

def validate_file_for_processing(file_path: str) -> tuple[bool, str]:
    """Validate if a file can be processed safely."""
    try:
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        if not os.path.isfile(file_path):
            return False, "Path is not a file"
        
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return False, "File is empty"
        
        # Check file size limit (50MB)
        max_size = 50 * 1024 * 1024
        if file_size > max_size:
            return False, f"File too large ({file_size} bytes). Maximum allowed: {max_size} bytes"
        
        # Check file extension
        _, ext = os.path.splitext(file_path.lower())
        allowed_extensions = {'.png', '.jpg', '.jpeg', '.pdf'}
        if ext not in allowed_extensions:
            return False, f"Unsupported file type: {ext}. Allowed: {', '.join(allowed_extensions)}"
        
        return True, "File is valid for processing"
    
    except Exception as e:
        return False, f"Error validating file: {str(e)}"

if __name__ == '__main__':
    # quick smoke‐test when you run `python extractor.py`
    try:
        uploads = os.path.join(os.path.dirname(__file__), 'uploads')
        
        if not os.path.exists(uploads):
            print(f"Uploads directory not found: {uploads}")
            exit(1)
        
        for fname in os.listdir(uploads):
            path = os.path.join(uploads, fname)
            print(f"\n--- Processing {fname} ---")
            
            # Validate file first
            is_valid, message = validate_file_for_processing(path)
            if not is_valid:
                print(f"Skipping {fname}: {message}")
                continue
            
            try:
                if fname.lower().endswith(('.png', '.jpg', '.jpeg')):
                    text = extract_text_from_image(path)
                    print("OCR Result:")
                    print(text[:500] + "..." if len(text) > 500 else text)
                elif fname.lower().endswith('.pdf'):
                    text = extract_text_from_pdf(path)
                    print("PDF Text:")
                    print(text[:500] + "..." if len(text) > 500 else text)
            except (OCRError, PDFError, FileExtractionError) as e:
                print(f"Error processing {fname}: {e}")
            except Exception as e:
                print(f"Unexpected error processing {fname}: {e}")
                
    except Exception as e:
        print(f"Error in main: {e}")
