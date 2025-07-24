import os
import io
import csv
from datetime import datetime
from flask import Flask, request, render_template_string, url_for, redirect, flash, Response
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func

from models import Session, Transaction, Threshold, User
from extractor import extract_text_from_image, extract_text_from_pdf
from parser import parse_transactions, aggregate_transactions

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

# ─── Login manager ─────────────────────────────────────────────────────────────
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    session = Session()
    user = session.query(User).get(int(user_id))
    session.close()
    return user

# ─── Upload folder ─────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
        username = request.form['username']
        password = request.form['password']
        session = Session()
        if session.query(User).filter_by(username=username).first():
            flash('Username taken')
            session.close()
            return redirect(url_for('register'))
        user = User(username=username, password_hash=generate_password_hash(password))
        session.add(user)
        session.commit()
        session.close()
        flash('Registered! Please log in.')
        return redirect(url_for('login'))
    return render_template_string(REGISTER_FORM)

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session = Session()
        user = session.query(User).filter_by(username=username).first()
        session.close()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'error')
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

    for f in request.files.getlist('file'):
        filename = secure_filename(f.filename)
        dest = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(dest)

        # extract
        ext = filename.lower().rsplit('.', 1)[-1]
        if ext in ('png','jpg','jpeg'):
            text = extract_text_from_image(dest)
        elif ext == 'pdf':
            text = extract_text_from_pdf(dest)
        else:
            text = '<unsupported file type>'

        results[filename] = text
        txs = parse_transactions(text)
        all_transactions.extend(txs)

        # persist (no duplicates)
        session = Session()
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
        session.commit()
        session.close()

    # threshold alerts
    summary = aggregate_transactions(all_transactions)
    warnings = []
    session = Session()
    for desc,total in summary.items():
        thr = session.query(Threshold).filter_by(user_id=user_id, category=desc).first()
        if thr and total>thr.limit:
            warnings.append(f"{desc} exceeded ${thr.limit:.2f}")
    session.close()

    # build response
    html = []
    if warnings:
        html.extend(['<h2 style="color:red;">⚠️ Alerts</h2>','<ul>'])
        html.extend(f"<li>{w}</li>" for w in warnings)
        html.append('</ul>')

    html.append('<h1>Extraction Results</h1>')
    for fname,txt in results.items():
        html.append(f'<h2>{fname}</h2><pre style="white-space:pre-wrap;">{txt}</pre>')

    html.append('<h1>Top Spending</h1><ul>')
    for d,t in sorted(summary.items(), key=lambda x:x[1], reverse=True):
        html.append(f'<li>{d}: ${t:.2f}</li>')
    html.append('</ul>')

    return '\n'.join(html)

# ─── Protected: History ─────────────────────────────────────────────────────────
@app.route('/history')
@login_required
def history():
    # raw inputs
    start = request.args.get('start', '')
    end   = request.args.get('end', '')

    # normalize to ISO (YYYY-MM-DD)
    def normalize(d):
        try:
            return datetime.fromisoformat(d).date().isoformat()
        except:
            return ''
    start_iso = normalize(start)
    end_iso   = normalize(end)

    # query
    session = Session()
    q = session.query(Transaction).filter_by(user_id=current_user.id)
    if start_iso:
        q = q.filter(func.date(Transaction.timestamp) >= start_iso)
    if end_iso:
        q = q.filter(func.date(Transaction.timestamp) <= end_iso)
    txs = q.order_by(Transaction.timestamp).all()
    session.close()

    # render
    html = [
        BASE_NAV,
        '<h1>History</h1>',
        '<form method="get">',
        f'Start: <input name="start" type="date" value="{start_iso}"> ',
        f'End:   <input name="end"   type="date" value="{end_iso}"> ',
        '<input type="submit" value="Filter">',
        '</form>',
        '<table border="1" cellpadding="5">',
        '<tr><th>ID</th><th>Date</th><th>File</th><th>Description</th><th>Amount</th></tr>'
    ]
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
    html.append('</table>')
    return '\n'.join(html)

# ─── Protected: Monthly Summary ─────────────────────────────────────────────────
@app.route('/summary')
@login_required
def summary_view():
    session = Session()
    data = (
        session.query(
            func.strftime('%Y-%m', Transaction.timestamp).label('month'),
            func.sum(Transaction.amount).label('total')
        )
        .filter_by(user_id=current_user.id)
        .group_by('month')
        .all()
    )
    session.close()

    html = [
        BASE_NAV,
        '<h1>Monthly Summary</h1>',
        '<table border="1" cellpadding="5">',
        '<tr><th>Month</th><th>Total</th></tr>'
    ]
    for m,t in data:
        html.append(f'<tr><td>{m}</td><td>${t:.2f}</td></tr>')
    html.append('</table>')
    return '\n'.join(html)

# ─── Protected: Export CSV ───────────────────────────────────────────────────────
@app.route('/export.csv')
@login_required
def export_csv():
    session = Session()
    rows = session.query(Transaction).filter_by(user_id=current_user.id).all()
    session.close()

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID','Date','File','Description','Amount'])
    for tx in rows:
        cw.writerow([tx.id, tx.timestamp.isoformat(), tx.filename, tx.description, tx.amount])

    return Response(
        si.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition':'attachment;filename=expenses.csv'}
    )

# ─── Protected: Dashboard ──────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    session = Session()
    data = (
        session.query(
            Transaction.description,
            func.sum(Transaction.amount)
        )
        .filter_by(user_id=current_user.id)
        .group_by(Transaction.description)
        .all()
    )
    session.close()

    # group into top 8 + Other
    sorted_data = sorted(data, key=lambda t: t[1], reverse=True)
    top_n = 8
    top = sorted_data[:top_n]
    other_total = sum(amount for _, amount in sorted_data[top_n:])
    if other_total:
        top.append(("Other", other_total))

    labels = [d for d,_ in top]
    values = [v for _,v in top]

    return render_template_string(
    '''<!doctype html><title>Dashboard</title>''' + BASE_NAV + '''
    <h1>Spend by Category</h1>
    <canvas id="chart"></canvas>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
      new Chart(document.getElementById('chart'), {
        type: 'pie',
        data: {
          labels: {{ labels|tojson }},
          datasets: [{ data: {{ values|tojson }} }]
        }
      });
    </script>''',
    labels=labels, values=values)

if __name__ == '__main__':
    print('🔹 Starting Flask…')
    app.run(debug=True)
