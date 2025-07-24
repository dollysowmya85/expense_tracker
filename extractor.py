import os
import pytesseract
from PIL import Image
from PyPDF2 import PdfReader

# ← point to your tesseract.exe install location
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

def extract_text_from_image(path: str) -> str:
    """Run OCR on an image file."""
    img = Image.open(path)
    return pytesseract.image_to_string(img)

def extract_text_from_pdf(path: str) -> str:
    """Extract all text from a PDF file."""
    reader = PdfReader(path)
    full_text = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            full_text.append(text)
    return "\n".join(full_text)

if __name__ == '__main__':
    # quick smoke‐test when you run `python extractor.py`
    uploads = os.path.join(os.path.dirname(__file__), 'uploads')
    for fname in os.listdir(uploads):
        path = os.path.join(uploads, fname)
        print(f"\n--- {fname} ---")
        if fname.lower().endswith(('.png', '.jpg', '.jpeg')):
            print(extract_text_from_image(path))
        elif fname.lower().endswith('.pdf'):
            print(extract_text_from_pdf(path))
