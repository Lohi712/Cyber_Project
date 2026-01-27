from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "secure_vault_key"

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- 1. User Model (Authentication & Hashing with Salt) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    # NEW: Store the unique 16-character MFA secret key [cite: 5, 16]
    mfa_secret = db.Column(db.String(16), nullable=False)

# --- 2. Home/Login Route (Single-Factor Auth) ---
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        user_input = request.form.get('username')
        pass_input = request.form.get('password')
        
        # [cite_start]Check database for identity [cite: 5, 10]
        user = User.query.filter_by(username=user_input).first()
        
        # [cite_start]Verify hash match [cite: 16]
        if user and bcrypt.check_password_hash(user.password_hash, pass_input):
            session['temp_user_id'] = user.id
            return redirect(url_for('mfa_verify')) # Move to Step 2
        
        return "Invalid Username or Password"
    return render_template('login.html')

# --- 3. MFA Route (Multi-Factor Auth) ---
@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if 'temp_user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        otp = request.form.get('otp')
        # [cite_start]Simulation of possession factor [cite: 16]
        if otp == "123456":
            user = User.query.get(session['temp_user_id'])
            session['user_id'] = user.id
            session['role'] = user.role # Set role for Access Control [cite: 16]
            session.pop('temp_user_id', None)
            return "Logged In Successfully to Dashboard!" # We will build dashboard next
        
        return "Invalid OTP"
    return render_template('mfa.html')

# --- 4. Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        role = request.form.get('role')
        
        # [cite_start]Hashing with Salt implementation [cite: 16]
        hashed_pw = bcrypt.generate_password_hash(pw).decode('utf-8')
        
        new_user = User(username=user, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('register.html')

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)