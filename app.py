from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import random
import time
from datetime import datetime
import os
import re

app = Flask(__name__)
app.secret_key = 'finance_tracker_secret_2025'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
DEFAULT_PHOTO = '/static/images/default_avatar.png'

# Custom Jinja2 filter for float formatting
def format_float(value):
    return "{:.2f}".format(float(value) if value is not None else 0.00)

app.jinja_env.filters['format_float'] = format_float

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    return User(user_data[0], user_data[1]) if user_data else None

def init_db():
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE,
                  password TEXT,
                  is_verified INTEGER DEFAULT 0,
                  otp TEXT,
                  otp_expiry REAL,
                  name TEXT,
                  phone TEXT,
                  phone_verified INTEGER DEFAULT 0,
                  photo_path TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS expenses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  date TEXT,
                  amount_inr REAL,
                  original_amount REAL,
                  original_currency TEXT,
                  category TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS goals
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  name TEXT,
                  target REAL,
                  current REAL DEFAULT 0,
                  deadline TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Check and add new columns if they don't exist
    c.execute('PRAGMA table_info(users)')
    columns = {col[1] for col in c.fetchall()}
    if 'captcha_num1' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN captcha_num1 INTEGER")
    if 'captcha_num2' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN captcha_num2 INTEGER")
    if 'captcha_answer' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN captcha_answer INTEGER")
    if 'captcha_expiry' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN captcha_expiry REAL")
    
    c.execute('PRAGMA table_info(users)')
    columns = [col[1] for col in c.fetchall()]
    if 'phone_verified' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN phone_verified INTEGER DEFAULT 0")
        conn.commit()
    
    c.execute("UPDATE users SET photo_path = ? WHERE photo_path IS NULL OR photo_path = ''", (DEFAULT_PHOTO,))
    conn.commit()
    conn.close()

def send_otp_email(email, otp, is_phone=False):
    sender = "vigneshvignesh1974@gmail.com"  # Replace with your Gmail address
    password = "banffvzhliiamjux"   # Replace with your Gmail App Password
    subject = 'Finance Tracker Account Verification OTP' if not is_phone else 'Finance Tracker Phone Verification OTP'
    msg = MIMEText(f"Your OTP{' for account verification' if not is_phone else ' for phone verification'} is {otp}. It expires in 1 minute.")
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender, password)
            server.send_message(msg)
    except Exception as e:
        print(f"Failed to send email: {e}")
        flash('Failed to send OTP via email. Please try again later.', 'custom-danger')

# Exchange rates relative to INR (base currency)
exchange_rates = {
    'INR': 1.0,
    'USD': 83.0,
    'EUR': 90.0,
    'GBP': 105.0,
    'JPY': 0.55
}

def convert_to_inr(amount, currency):
    rate = exchange_rates.get(currency.upper(), 1.0)
    return amount * rate if rate else amount

def validate_name(name):
    return bool(re.match("^[a-zA-Z\s-]*$", name))

def validate_phone(phone):
    return bool(re.match(r'^\+[1-9][0-9]{0,2}\d{7,15}$', phone))

def generate_captcha():
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    return num1, num2, num1 + num2

def extract_phone_number(phone):
    if not phone or not validate_phone(phone):
        return ""
    # Extract digits after country code
    match = re.match(r'^\+([1-9][0-9]{0,2})(\d{7,15})$', phone)
    return match.group(2) if match else phone.replace('+', '').replace(match.group(1), '') if match else ""

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        otp = str(random.randint(1000, 9999))
        otp_expiry = time.time() + 60
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password, otp, otp_expiry, photo_path) VALUES (?, ?, ?, ?, ?)",
                      (email, password, otp, otp_expiry, DEFAULT_PHOTO))
            conn.commit()
            send_otp_email(email, otp)  # Email OTP for signup
            flash('An OTP has been sent to your email. Please verify it.', 'custom-info')
            session['email'] = email
            return redirect(url_for('verify_otp'))
        except sqlite3.IntegrityError:
            flash('Email already registered')
        finally:
            conn.close()
    theme = session.get('theme', 'light')
    return render_template('signup.html', theme=theme)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'email' not in session:
        return redirect(url_for('signup'))
    if request.method == 'POST':
        otp = request.form['otp']
        email = session['email']
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("SELECT id, email, otp, otp_expiry FROM users WHERE email = ?", (email,))
        user_data = c.fetchone()
        if user_data:
            if time.time() > user_data[3]:
                flash('OTP expired. Please sign up again or request a new one.', 'custom-danger')
            elif user_data[2] == otp:
                c.execute("UPDATE users SET is_verified = 1, otp = NULL, otp_expiry = NULL WHERE email = ?",
                          (email,))
                conn.commit()
                login_user(User(user_data[0], user_data[1]))
                conn.close()
                session.pop('email', None)
                flash('OTP Verified! Account Created Successfully', 'custom-success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP', 'custom-danger')
        conn.close()
    theme = session.get('theme', 'light')
    otp_expiry = session.get('otp_expiry', time.time() + 60) if 'email' in session else None
    time_remaining = max(0, int(otp_expiry - time.time())) if otp_expiry else 0
    return render_template('verify_otp.html', theme=theme, time_remaining=time_remaining)

@app.route('/resend_otp', methods=['GET'])
def resend_otp():
    if 'email' not in session:
        return redirect(url_for('signup'))
    email = session['email']
    otp = str(random.randint(1000, 9999))
    otp_expiry = time.time() + 60
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", (otp, otp_expiry, email))
    conn.commit()
    session['otp_expiry'] = otp_expiry
    conn.close()
    send_otp_email(email, otp)  # Email OTP for resend
    flash('A new OTP has been sent to your email. Please verify it.', 'custom-info')
    theme = session.get('theme', 'light')
    return redirect(url_for('verify_otp'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("SELECT id, email, password, is_verified FROM users WHERE email = ?", (email,))
        user_data = c.fetchone()
        conn.close()
        if user_data and check_password_hash(user_data[2], password) and user_data[3]:
            user = User(user_data[0], user_data[1])
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email/password or account not verified')
    theme = session.get('theme', 'light')
    prefilled_email = request.args.get('email', session.get('reset_email', ''))
    return render_template('login.html', theme=theme, prefilled_email=prefilled_email)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/')
def home():
    theme = session.get('theme', 'light')
    return render_template('home.html', theme=theme)

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("SELECT date, amount_inr, original_amount, original_currency, category FROM expenses WHERE user_id = ? ORDER BY date DESC", (current_user.id,))
    all_expenses = c.fetchall()
    
    current_month = datetime.now().strftime('%Y-%m')
    monthly_expenses = {}
    for exp in all_expenses:
        if exp[0]:
            try:
                month = exp[0][:7]
                monthly_expenses[month] = monthly_expenses.get(month, 0) + float(exp[1])
            except (ValueError, TypeError) as e:
                print(f"Error processing month for date {exp[0]}: {e}")
                continue
    
    yearly_expenses = {}
    for exp in all_expenses:
        if exp[0]:
            try:
                year = datetime.strptime(exp[0], '%Y-%m-%d').year
                yearly_expenses[year] = yearly_expenses.get(year, 0) + float(exp[1])
            except (ValueError, TypeError) as e:
                print(f"Error processing year for date {exp[0]}: {e}")
                continue
    
    current_year = datetime.now().year
    years_with_data = [year for year in yearly_expenses.keys() if yearly_expenses[year] > 0]
    start_year = max(2020, min(years_with_data or [current_year], default=current_year))
    yearly_expenses = {y: yearly_expenses.get(y, 0) for y in range(start_year, current_year + 1)}
    
    recent_expenses = all_expenses[:30]
    
    total_spending = sum(float(exp[1]) for exp in all_expenses if exp[1] is not None) if all_expenses else 0
    days = len([exp for exp in all_expenses if exp[1] is not None]) or 1
    avg_daily_spending = total_spending / days if days > 0 else 0
    predicted_monthly_spending = avg_daily_spending * 30
    
    budget_threshold = predicted_monthly_spending * 0.8
    spending_alert = None
    if total_spending > budget_threshold:
        spending_alert = f"Warning: Spending (₹{total_spending|format_float}) exceeds 80% of predicted budget (₹{predicted_monthly_spending|format_float})!"

    c.execute("SELECT category, SUM(amount_inr) FROM expenses WHERE user_id = ? GROUP BY category",
              (current_user.id,))
    spending_data = c.fetchall()
    labels = [row[0] for row in spending_data]
    values = [float(row[1]) for row in spending_data if row[1] is not None]
    
    c.execute("SELECT name, target, current, deadline FROM goals WHERE user_id = ?", (current_user.id,))
    goals = c.fetchall()
    c.execute("SELECT photo_path FROM users WHERE id = ?", (current_user.id,))
    user_profile = c.fetchone()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('dashboard.html', labels=labels, values=values, goals=goals,
                          total_spending=total_spending, spending_alert=spending_alert,
                          recent_expenses=recent_expenses, monthly_expenses=monthly_expenses,
                          yearly_expenses=yearly_expenses, current_month=current_month,
                          user_profile=user_profile, theme=theme)

@app.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    session['theme'] = 'dark' if session.get('theme', 'light') == 'light' else 'light'
    return jsonify({'theme': session['theme']})

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    c.execute("SELECT id, email, name, phone, phone_verified, photo_path FROM users WHERE id = ?", (current_user.id,))
    user_data = c.fetchone()
    
    # Parse phone number to separate country code and number
    country_code = '+91'  # Default to India
    phone_number = ''
    if user_data and user_data[3] and validate_phone(user_data[3]):
        match = re.match(r'^\+([1-9][0-9]{0,2})(\d{10})$', user_data[3])  # Expect exactly 10 digits
        if match:
            country_code = f"+{match.group(1)}"
            phone_number = match.group(2)
        else:
            phone_number = extract_phone_number(user_data[3])
    print(f"Loaded phone: {user_data[3]}, country_code: {country_code}, phone_number: {phone_number}")  # Debug

    if request.method == 'POST':
        print("Form data received:", request.form)  # Debug form submission
        if 'verify' in request.form:  # Handle verify phone
            country_code = request.form.get('country_code', '+91')
            phone_number = request.form.get('phone_number', '').strip()
            full_phone = f"{country_code}{phone_number}"
            if phone_number and validate_phone(full_phone) and len(phone_number) == 10:
                num1, num2, answer = generate_captcha()
                c.execute("UPDATE users SET phone = ?, captcha_num1 = ?, captcha_num2 = ?, captcha_answer = ?, captcha_expiry = ? WHERE id = ?", 
                          (full_phone, num1, num2, answer, time.time() + 60, current_user.id))
                conn.commit()
                session['captcha_num1'] = num1
                session['captcha_num2'] = num2
                session['captcha_answer'] = answer
                session['captcha_expiry'] = time.time() + 60
                flash('Please solve the CAPTCHA to verify your phone number.', 'custom-info')
                return redirect(url_for('verify_phone_otp'))
            else:
                flash('Invalid phone number format. Must be 10 digits.', 'custom-danger')
                return redirect(url_for('profile'))
        else:  # Handle profile update
            name = request.form.get('name', '')
            if not validate_name(name):
                flash('Name can only contain letters, spaces, and hyphens!', 'custom-danger')
                return redirect(url_for('profile'))
            country_code = request.form.get('country_code', '+91')
            phone_number = request.form.get('phone_number', '').strip()
            full_phone = f"{country_code}{phone_number}" if phone_number else (user_data[3] if user_data else '')
            if full_phone and not validate_phone(full_phone) or (phone_number and len(phone_number) != 10):
                flash('Invalid phone number format. Use 10 digits with a valid country code.', 'custom-danger')
                return redirect(url_for('profile'))
            photo = request.files.get('photo')
            photo_path = user_data[5] if user_data else DEFAULT_PHOTO
            
            if photo and photo.filename:
                filename = f"{current_user.id}_{photo.filename}"
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(photo_path)
                photo_path = f"/static/uploads/{filename}"
            
            c.execute("UPDATE users SET name = ?, phone = ?, photo_path = ? WHERE id = ?", 
                      (name or (user_data[2] if user_data else ''), full_phone, photo_path, current_user.id))
            conn.commit()
            print(f"Updated phone: {full_phone}, rows affected: {c.rowcount}")  # Debug
            if c.rowcount > 0:
                flash('Profile updated successfully!', 'custom-success')
            else:
                flash('No changes made or update failed.', 'custom-danger')
            return redirect(url_for('profile'))
    
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('profile.html', user_data=user_data, theme=theme, country_code=country_code, phone_number=phone_number)

@app.route('/verify_phone_otp', methods=['GET', 'POST'])
@login_required
def verify_phone_otp():
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    try:
        c.execute("SELECT captcha_num1, captcha_num2, captcha_answer, captcha_expiry FROM users WHERE id = ?", (current_user.id,))
        captcha_data = c.fetchone()

        if not captcha_data or time.time() > captcha_data[3]:
            flash('CAPTCHA expired or not generated. Please request verification again.', 'custom-danger')
            return redirect(url_for('profile'))

        num1, num2, answer, expiry = captcha_data
        session['captcha_num1'] = num1
        session['captcha_num2'] = num2
        session['captcha_answer'] = answer
        session['captcha_expiry'] = expiry

        if request.method == 'POST':
            user_answer = request.form.get('captcha_answer', '')
            try:
                user_answer = int(user_answer)
                if user_answer == answer:
                    c.execute("UPDATE users SET phone_verified = 1, captcha_num1 = NULL, captcha_num2 = NULL, captcha_answer = NULL, captcha_expiry = NULL WHERE id = ?", (current_user.id,))
                    conn.commit()
                    session.pop('captcha_num1', None)
                    session.pop('captcha_num2', None)
                    session.pop('captcha_answer', None)
                    session.pop('captcha_expiry', None)
                    flash('Phone number verified successfully! ✓', 'custom-success')
                    return redirect(url_for('profile'))
                else:
                    flash('Incorrect CAPTCHA answer.', 'custom-danger')
            except ValueError:
                flash('Please enter a valid number.', 'custom-danger')
    finally:
        conn.close()
    theme = session.get('theme', 'light')
    time_remaining = max(0, int(session.get('captcha_expiry', 0) - time.time()))
    return render_template('verify_phone_otp.html', theme=theme, time_remaining=time_remaining, num1=num1, num2=num2)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        date = request.form['date']
        amount = float(request.form['amount'])
        currency = request.form['currency'].upper()
        category = request.form['category']
        amount_inr = convert_to_inr(amount, currency)
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        print(f"Adding expense with date: {date}, amount_inr: {amount_inr}")
        c.execute("INSERT INTO expenses (user_id, date, amount_inr, original_amount, original_currency, category) VALUES (?, ?, ?, ?, ?, ?)",
                  (current_user.id, date, amount_inr, amount, currency, category))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))
    theme = session.get('theme', 'light')
    return render_template('add_expense.html', currencies=list(exchange_rates.keys()), theme=theme)

@app.route('/add_goal', methods=['GET', 'POST'])
@login_required
def add_goal():
    conn = sqlite3.connect('expenses.db')
    c = conn.cursor()
    if request.method == 'POST':
        name = request.form['name']
        target = float(request.form['target'])
        deadline = request.form['deadline']
        c.execute("INSERT INTO goals (user_id, name, target, current, deadline) VALUES (?, ?, ?, ?, ?)",
                  (current_user.id, name, target, 0, deadline))
        conn.commit()
    conn.close()
    theme = session.get('theme', 'light')
    return render_template('add_goal.html', theme=theme)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("SELECT id, email, is_verified FROM users WHERE email = ?", (email,))
        user_data = c.fetchone()
        conn.close()
        if user_data and user_data[2]:  # Check if user exists and is verified
            otp = str(random.randint(1000, 9999))
            otp_expiry = time.time() + 60
            conn = sqlite3.connect('expenses.db')
            c = conn.cursor()
            c.execute("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", (otp, otp_expiry, email))
            conn.commit()
            send_otp_email(email, otp)  # Email OTP for password reset
            flash('An OTP has been sent to your email. Please verify it.', 'custom-info')
            session['reset_email'] = email
            session['reset_otp_expiry'] = otp_expiry  # Store expiry for timer
            conn.close()
            return redirect(url_for('verify_reset_otp'))
        else:
            flash('Email not found or not verified.', 'custom-danger')
    theme = session.get('theme', 'light')
    return render_template('forgot_password.html', theme=theme)

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if 'reset_email' not in session or 'reset_otp_expiry' not in session:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        otp = request.form.get('otp', '')
        email = session['reset_email']
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("SELECT otp, otp_expiry FROM users WHERE email = ?", (email,))
        otp_data = c.fetchone()
        if otp_data:
            if time.time() > otp_data[1]:
                flash('OTP expired. Request a new one.', 'custom-danger')
            elif otp_data[0] == otp:
                session['reset_verified'] = True
                conn.close()
                return redirect(url_for('reset_password'))
            else:
                flash('Invalid OTP.', 'custom-danger')
        conn.close()
    theme = session.get('theme', 'light')
    otp_expiry = session.get('reset_otp_expiry')
    time_remaining = max(0, int(otp_expiry - time.time())) if otp_expiry else 0
    return render_template('verify_reset_otp.html', theme=theme, email=session.get('reset_email'), time_remaining=time_remaining)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session or 'reset_verified' not in session:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = session['reset_email']
        conn = sqlite3.connect('expenses.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE email = ?", (email,))
        old_password_hash = c.fetchone()[0] if c.fetchone() else None
        
        if new_password != confirm_password:
            flash('New password and confirmation do not match!', 'custom-danger')
            return redirect(url_for('reset_password'))
        if old_password_hash and check_password_hash(old_password_hash, new_password):
            flash('New password cannot be the same as the old password!', 'custom-danger')
            return redirect(url_for('reset_password'))
        
        new_password_hash = generate_password_hash(new_password)
        c.execute("UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE email = ?", (new_password_hash, email))
        conn.commit()
        session.pop('reset_email', None)
        session.pop('reset_verified', None)
        session.pop('reset_otp_expiry', None)
        conn.close()
        flash('Password reset successfully. Please login.', 'custom-success')
        return redirect(url_for('login', email=email))  # Redirect with email pre-filled
    theme = session.get('theme', 'light')
    return render_template('reset_password.html', theme=theme, email=session.get('reset_email'))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)