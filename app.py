# all libraries import
import os
import io
import csv
import logging
import traceback
from datetime import datetime
from flask import Flask, request, render_template_string, url_for, redirect, flash, Response, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge, BadRequest
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from models import Session, Transaction, Threshold, User
from extractor import extract_text_from_image, extract_text_from_pdf, FileExtractionError, OCRError, PDFError
from parser import parse_transactions, aggregate_transactions, TransactionParsingError, AggregationError

# ─── Configure Logging ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('expense_tracker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# ─── Error Handler Classes ─────────────────────────────────────────────────────
class ExpenseTrackerError(Exception):
    """Base exception for expense tracker errors"""
    pass

class FileProcessingError(ExpenseTrackerError):
    """Error during file processing"""
    pass

class DatabaseError(ExpenseTrackerError):
    """Database operation error"""
    pass

class AuthenticationError(ExpenseTrackerError):
    """Authentication related error"""
    pass

# ─── Global Error Handlers ─────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 error: {request.url}")
    return render_template_string('''
    <!doctype html>
    <title>Page Not Found</title>
    <h1>Page Not Found</h1>
    <p>The page you're looking for doesn't exist.</p>
    <a href="{{ url_for('index') }}">Go back to home</a>
    '''), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")
    logger.error(f"Traceback: {traceback.format_exc()}")
    return render_template_string('''
    <!doctype html>
    <title>Internal Server Error</title>
    <h1>Something went wrong</h1>
    <p>An internal error occurred. Please try again later.</p>
    <a href="{{ url_for('index') }}">Go back to home</a>
    '''), 500

@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    logger.warning("File upload too large")
    flash('File is too large. Maximum size is 50MB.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(BadRequest)
def bad_request(error):
    logger.warning(f"Bad request: {str(error)}")
    flash('Bad request. Please check your input.', 'error')
    return redirect(url_for('index'))

# ─── Database Session Helper ───────────────────────────────────────────────────
def get_db_session():
    """Get database session with error handling"""
    try:
        return Session()
    except SQLAlchemyError as e:
        logger.error(f"Database connection error: {str(e)}")
        raise DatabaseError("Failed to connect to database")

def safe_db_operation(operation, *args, **kwargs):
    """Execute database operation with proper error handling"""
    session = None
    try:
        session = get_db_session()
        result = operation(session, *args, **kwargs)
        session.commit()
        return result
    except IntegrityError as e:
        if session:
            session.rollback()
        logger.error(f"Database integrity error: {str(e)}")
        raise DatabaseError("Data integrity violation")
    except SQLAlchemyError as e:
        if session:
            session.rollback()
        logger.error(f"Database error: {str(e)}")
        raise DatabaseError("Database operation failed")
    except Exception as e:
        if session:
            session.rollback()
        logger.error(f"Unexpected error in database operation: {str(e)}")
        raise DatabaseError("Unexpected database error")
    finally:
        if session:
            session.close()

# ─── Login manager ─────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    try:
        return safe_db_operation(lambda session: session.query(User).get(int(user_id)))
    except (DatabaseError, ValueError) as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

# ─── Upload folder ─────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
except OSError as e:
    logger.error(f"Failed to create upload folder: {str(e)}")
    raise ExpenseTrackerError("Failed to initialize upload directory")

# ─── Shared HTML snippets ──────────────────────────────────────────────────────
BASE_NAV = '''
<nav>
  <a href="{{ url_for('index') }}">Upload</a> |
  <a href="{{ url_for('history') }}">History</a> |
  <a href="{{ url_for('summary_view') }}">Monthly</a> |
  <a href="{{ url_for('dashboard') }}">Dashboard</a> |
  <a href="{{ url_for('export_csv') }}">Export CSV</a> |
  <a href="{{ url_for('logout') }}">Logout</a>
</nav><hr>
'''

LOGIN_FORM = '''
<!doctype html>
<title>Login</title>
<h1>Login</h1>
<form method="post">
  Username: <input name="username">
  Password: <input name="password" type="password">
  <input type="submit" value="Login">
</form>
<p>Or <a href="{{ url_for('register') }}">Register</a></p>
'''

REGISTER_FORM = '''
<!doctype html>
<title>Register</title>
<h1>Register</h1>
<form method="post">
  Username: <input name="username">
  Password: <input name="password" type="password">
  <input type="submit" value="Register">
</form>
<p>Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
'''

UPLOAD_FORM = '''
<!doctype html>
<title>Upload Expense Documents</title>
<h1>Upload Receipts / Statements</h1>
<form method="post" enctype="multipart/form-data" action="{{ url_for('upload') }}">
  <input type="file" name="file" multiple accept="*/*">
  <input type="submit" value="Upload">
</form>
''' + BASE_NAV

# ─── Auth routes ────────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('register'))
        
        try:
            def register_user(session):
                # Check if user exists
                existing_user = session.query(User).filter_by(username=username).first()
                if existing_user:
                    return None  # User exists
                
                # Create new user
                user = User(username=username, password_hash=generate_password_hash(password))
                session.add(user)
                return user
            
            result = safe_db_operation(register_user)
            if result is None:
                flash('Username already taken', 'error')
                return redirect(url_for('register'))
            
            logger.info(f"New user registered: {username}")
            flash('Registered successfully! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except DatabaseError as e:
            logger.error(f"Database error during registration for {username}: {str(e)}")
            flash('Registration failed due to database error', 'error')
            return redirect(url_for('register'))
        except Exception as e:
            logger.error(f"Unexpected error during registration for {username}: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))
    
    return render_template_string(REGISTER_FORM)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template_string(LOGIN_FORM)
        
        try:
            def get_user(session):
                return session.query(User).filter_by(username=username).first()
            
            user = safe_db_operation(get_user)
            
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                logger.info(f"User logged in: {username}")
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            else:
                logger.warning(f"Failed login attempt for: {username}")
                flash('Invalid username or password', 'error')
                
        except DatabaseError as e:
            logger.error(f"Database error during login for {username}: {str(e)}")
            flash('Login failed due to database error', 'error')
        except Exception as e:
            logger.error(f"Unexpected error during login for {username}: {str(e)}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template_string(LOGIN_FORM)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ─── Protected: Upload ─────────────────────────────────────────────────────────
@app.route('/', methods=['GET'])
@login_required
def index():
    return render_template_string(UPLOAD_FORM)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    user_id = current_user.id
    results = {}
    all_transactions = []

    try:
        files = request.files.getlist('file')
        if not files or not any(f.filename for f in files):
            flash('No files selected for upload.', 'error')
            return redirect(url_for('index'))

        logger.info(f"Processing {len(files)} files for user {user_id}")

        for f in files:
            if not f.filename:
                continue
                
            filename = secure_filename(f.filename)
            if not filename:
                logger.warning("Skipping file with invalid name")
                continue
                
            dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                f.save(dest)
                logger.info(f"Saved file: {filename}")
            except Exception as e:
                logger.error(f"Error saving file {filename}: {str(e)}")
                flash(f'Error saving file {filename}', 'error')
                continue

            # extract text
            try:
                ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
                
                if ext in ('png','jpg','jpeg'):
                    text = extract_text_from_image(dest)
                elif ext == 'pdf':
                    text = extract_text_from_pdf(dest)
                else:
                    text = '<unsupported file type>'
                    logger.warning(f"Unsupported file type: {ext} for file {filename}")

                results[filename] = text
                logger.info(f"Text extracted from {filename}: {len(text)} characters")
                
            except (OCRError, PDFError, FileExtractionError) as e:
                logger.error(f"Text extraction error for {filename}: {str(e)}")
                flash(f'Error extracting text from {filename}: {str(e)}', 'error')
                results[filename] = f'<extraction error: {str(e)}>'
                continue
            except Exception as e:
                logger.error(f"Unexpected error extracting text from {filename}: {str(e)}")
                flash(f'Unexpected error processing {filename}', 'error')
                results[filename] = f'<unexpected error: {str(e)}>'
                continue

            # parse transactions
            try:
                txs = parse_transactions(text)
                all_transactions.extend(txs)
                logger.info(f"Parsed {len(txs)} transactions from {filename}")
            except TransactionParsingError as e:
                logger.error(f"Transaction parsing error for {filename}: {str(e)}")
                flash(f'Error parsing transactions from {filename}: {str(e)}', 'error')
                continue
            except Exception as e:
                logger.error(f"Unexpected error parsing transactions from {filename}: {str(e)}")
                flash(f'Unexpected error parsing transactions from {filename}', 'error')
                continue

            # persist transactions (no duplicates)
            try:
                def save_transactions(session):
                    saved_count = 0
                    for tx in txs:
                        exists = session.query(Transaction).filter_by(
                            user_id=user_id,
                            filename=filename,
                            description=tx["description"],
                            amount=tx["amount"]
                        ).first()
                        
                        if not exists:
                            session.add(Transaction(
                                user_id=user_id,
                                filename=filename,
                                description=tx["description"],
                                amount=tx["amount"]
                            ))
                            saved_count += 1
                    return saved_count
                
                saved_count = safe_db_operation(save_transactions)
                logger.info(f"Saved {saved_count} new transactions from {filename}")
                
            except DatabaseError as e:
                logger.error(f"Database error saving transactions for {filename}: {str(e)}")
                flash(f'Error saving transactions from {filename}', 'error')
                continue
            except Exception as e:
                logger.error(f"Unexpected error saving transactions for {filename}: {str(e)}")
                flash(f'Unexpected error saving transactions from {filename}', 'error')
                continue

        # Generate summary and threshold alerts
        summary = {}
        warnings = []
        
        try:
            if all_transactions:
                summary = aggregate_transactions(all_transactions)
                logger.info(f"Generated summary with {len(summary)} categories")
                
                # Check thresholds
                def check_thresholds(session):
                    threshold_warnings = []
                    for desc, total in summary.items():
                        threshold = session.query(Threshold).filter_by(
                            user_id=user_id, 
                            category=desc
                        ).first()
                        
                        if threshold and total > threshold.limit:
                            threshold_warnings.append(f"{desc} exceeded ${threshold.limit:.2f} (spent: ${total:.2f})")
                    return threshold_warnings
                
                warnings = safe_db_operation(check_thresholds)
                logger.info(f"Generated {len(warnings)} threshold warnings")
                
        except (AggregationError, DatabaseError) as e:
            logger.error(f"Error generating summary or checking thresholds: {str(e)}")
            flash('Error generating spending summary', 'error')
        except Exception as e:
            logger.error(f"Unexpected error in summary generation: {str(e)}")
            flash('Unexpected error generating summary', 'error')

        # build response
        html = []
        
        if warnings:
            html.extend(['<h2 style="color:red;">⚠️ Spending Alerts</h2>','<ul>'])
            html.extend(f"<li>{w}</li>" for w in warnings)
            html.append('</ul>')

        html.append('<h1>File Processing Results</h1>')
        for fname, txt in results.items():
            html.append(f'<h2>{fname}</h2>')
            if txt.startswith('<'):
                html.append(f'<div style="color:red;">{txt}</div>')
            else:
                html.append(f'<pre style="white-space:pre-wrap; max-height:300px; overflow-y:auto;">{txt[:1000]}{"..." if len(txt) > 1000 else ""}</pre>')

        html.append('<h1>Spending Summary</h1>')
        if summary:
            html.append('<ul>')
            for desc, total in sorted(summary.items(), key=lambda x: x[1], reverse=True):
                html.append(f'<li>{desc}: ${total:.2f}</li>')
            html.append('</ul>')
        else:
            html.append('<p>No transactions found in uploaded files.</p>')

        html.append('<br><a href="/">Upload More Files</a> | <a href="/history">View History</a>')
        
        return '\n'.join(html)

    except Exception as e:
        logger.error(f"Unexpected error in upload route: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('An unexpected error occurred during file upload', 'error')
        return redirect(url_for('index'))

# ─── Protected: History ─────────────────────────────────────────────────────────
@app.route('/history')
@login_required
def history():
    # raw inputs
    start = request.args.get('start', '').strip()
    end = request.args.get('end', '').strip()

    # normalize to ISO (YYYY-MM-DD)
    def normalize(d):
        try:
            return datetime.fromisoformat(d).date().isoformat()
        except:
            return ''
    
    start_iso = normalize(start)
    end_iso = normalize(end)

    try:
        def get_filtered_transactions(session):
            q = session.query(Transaction).filter_by(user_id=current_user.id)
            if start_iso:
                q = q.filter(func.date(Transaction.timestamp) >= start_iso)
            if end_iso:
                q = q.filter(func.date(Transaction.timestamp) <= end_iso)
            return q.order_by(Transaction.timestamp).all()
        
        txs = safe_db_operation(get_filtered_transactions)
        logger.info(f"Retrieved {len(txs)} transactions for user {current_user.id}")
        
    except DatabaseError as e:
        logger.error(f"Database error fetching history for user {current_user.id}: {str(e)}")
        flash('Error fetching transaction history', 'error')
        txs = []
    except Exception as e:
        logger.error(f"Unexpected error fetching history for user {current_user.id}: {str(e)}")
        flash('Unexpected error fetching transaction history', 'error')
        txs = []

    # render
    html = [
        BASE_NAV,
        '<h1>Transaction History</h1>',
        '<form method="get">',
        f'Start Date: <input name="start" type="date" value="{start_iso}"> ',
        f'End Date: <input name="end" type="date" value="{end_iso}"> ',
        '<input type="submit" value="Filter">',
        '</form>',
        '<table border="1" cellpadding="5" style="border-collapse: collapse; width: 100%;">',
        '<tr style="background-color: #f0f0f0;"><th>ID</th><th>Date</th><th>File</th><th>Description</th><th>Amount</th></tr>'
    ]
    
    if txs:
        for tx in txs:
            html.append(
                f'<tr>'
                f'<td>{tx.id}</td>'
                f'<td>{tx.timestamp.date()}</td>'
                f'<td>{tx.filename}</td>'
                f'<td>{tx.description}</td>'
                f'<td>${tx.amount:.2f}</td>'
                '</tr>'
            )
    else:
        html.append('<tr><td colspan="5" style="text-align: center;">No transactions found</td></tr>')
    
    html.append('</table>')
    return '\n'.join(html)

# ─── Protected: Monthly Summary ─────────────────────────────────────────────────
@app.route('/summary')
@login_required
def summary_view():
    try:
        def get_monthly_summary(session):
            return (
                session.query(
                    func.strftime('%Y-%m', Transaction.timestamp).label('month'),
                    func.sum(Transaction.amount).label('total')
                )
                .filter_by(user_id=current_user.id)
                .group_by('month')
                .order_by('month')
                .all()
            )
        
        data = safe_db_operation(get_monthly_summary)
        logger.info(f"Retrieved monthly summary for user {current_user.id}: {len(data)} months")
        
    except DatabaseError as e:
        logger.error(f"Database error fetching monthly summary for user {current_user.id}: {str(e)}")
        flash('Error fetching monthly summary', 'error')
        data = []
    except Exception as e:
        logger.error(f"Unexpected error fetching monthly summary for user {current_user.id}: {str(e)}")
        flash('Unexpected error fetching monthly summary', 'error')
        data = []

    html = [
        BASE_NAV,
        '<h1>Monthly Summary</h1>',
        '<table border="1" cellpadding="5" style="border-collapse: collapse;">',
        '<tr style="background-color: #f0f0f0;"><th>Month</th><th>Total Spent</th></tr>'
    ]
    
    if data:
        for month, total in data:
            html.append(f'<tr><td>{month}</td><td>${total:.2f}</td></tr>')
    else:
        html.append('<tr><td colspan="2" style="text-align: center;">No data available</td></tr>')
    
    html.append('</table>')
    return '\n'.join(html)

# ─── Protected: Export CSV ───────────────────────────────────────────────────────
@app.route('/export.csv')
@login_required
def export_csv():
    try:
        def get_all_transactions(session):
            return session.query(Transaction).filter_by(user_id=current_user.id).order_by(Transaction.timestamp).all()
        
        rows = safe_db_operation(get_all_transactions)
        logger.info(f"Exporting {len(rows)} transactions for user {current_user.id}")
        
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID','Date','Time','File','Description','Amount'])
        
        for tx in rows:
            cw.writerow([
                tx.id, 
                tx.timestamp.date().isoformat(), 
                tx.timestamp.time().isoformat(), 
                tx.filename, 
                tx.description, 
                tx.amount
            ])

        response = Response(
            si.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename=expenses_{current_user.username}_{datetime.now().strftime("%Y%m%d")}.csv'}
        )
        return response
        
    except DatabaseError as e:
        logger.error(f"Database error during CSV export for user {current_user.id}: {str(e)}")
        flash('Error exporting data to CSV', 'error')
        return redirect(url_for('history'))
    except Exception as e:
        logger.error(f"Unexpected error during CSV export for user {current_user.id}: {str(e)}")
        flash('Unexpected error during CSV export', 'error')
        return redirect(url_for('history'))

# ─── Protected: Dashboard ──────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        def get_spending_by_category(session):
            return (
                session.query(
                    Transaction.description,
                    func.sum(Transaction.amount)
                )
                .filter_by(user_id=current_user.id)
                .group_by(Transaction.description)
                .order_by(func.sum(Transaction.amount).desc())
                .all()
            )
        
        data = safe_db_operation(get_spending_by_category)
        logger.info(f"Retrieved dashboard data for user {current_user.id}: {len(data)} categories")
        
    except DatabaseError as e:
        logger.error(f"Database error fetching dashboard data for user {current_user.id}: {str(e)}")
        flash('Error fetching dashboard data', 'error')
        data = []
    except Exception as e:
        logger.error(f"Unexpected error fetching dashboard data for user {current_user.id}: {str(e)}")
        flash('Unexpected error fetching dashboard data', 'error')
        data = []

    # group into top 8 + Other
    top_n = 8
    top = data[:top_n] if data else []
    other_total = sum(amount for _, amount in data[top_n:]) if len(data) > top_n else 0
    
    if other_total > 0:
        top.append(("Other", other_total))

    labels = [desc for desc, _ in top]
    values = [float(amount) for _, amount in top]

    return render_template_string(
    '''<!doctype html><title>Dashboard</title>''' + BASE_NAV + '''
    <h1>Spending by Category</h1>
    ''' + ('''
    <canvas id="chart" width="400" height="400"></canvas>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
      new Chart(document.getElementById('chart'), {
        type: 'pie',
        data: {
          labels: {{ labels|tojson }},
          datasets: [{ 
            data: {{ values|tojson }},
            backgroundColor: [
              '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0',
              '#9966FF', '#FF9F40', '#FF6384', '#C9CBCF'
            ]
          }]
        },
        options: {
          responsive: true,
          plugins: {
            legend: { position: 'right' }
          }
        }
      });
    </script>''' if labels and values else '<p>No spending data available for chart.</p>'),
    labels=labels, values=values)

if __name__ == '__main__':
    print('🔹 Starting Flask…')
    app.run(debug=True)
