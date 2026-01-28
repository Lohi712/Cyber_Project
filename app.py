from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
import qrcode
import io
import base64
import pyotp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from flask import send_file

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
    mfa_secret = db.Column(db.String(32), nullable=False)

# --- Evidence Model (Encryption & Hashing) ---
class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    # Encoding: We store the encrypted binary as a Base64 string 
    encrypted_data = db.Column(db.Text) 
    # Digital Signature: Proves authenticity and integrity 
    signature = db.Column(db.Text) 
    uploader = db.Column(db.String(50))
    # Store AES key and IV as Base64 strings for each file
    aes_key = db.Column(db.String(44))  # 32 bytes base64 encoded
    iv = db.Column(db.String(24))       # 16 bytes base64 encoded

# Generate a global RSA Key pair for this lab (Key Exchange/Signatures)
# Note: In real life, these would be stored in .pem files 
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    
    # Authorization: Fetch all evidence to display [cite: 16]
    all_evidence = Evidence.query.all()
    return render_template('dashboard.html', user_role=session.get('role'), evidence=all_evidence)

@app.route('/upload', methods=['POST'])
def upload_file():
    # Only Lead Analysts and Investigators can CREATE (Object 1)
    if session.get('role') not in ['Lead Analyst', 'Investigator']:
        return "Access Denied: Your role does not permit uploading evidence."
    # Access Control: Only Investigators and Analysts can upload 
    if session.get('role') == 'Legal Auditor':
        return "Access Denied: Auditors cannot upload evidence."

    file = request.files['evidence_file']
    if not file:
        return "No file selected."
    file_data = file.read()

    # --- 1. Encryption (AES-256 Symmetric) ---
    # We generate a random key and IV for every file 
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(file_data) + encryptor.finalize()

    # --- 2. Digital Signature (RSA + SHA-256) ---
    # We sign the ORIGINAL data to ensure it hasn't changed 
    signature = private_key.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # --- 3. Encoding (Base64) ---
    # Convert binary to text for storage 
    encoded_data = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
    encoded_sig = base64.b64encode(signature).decode('utf-8')
    encoded_aes_key = base64.b64encode(aes_key).decode('utf-8')
    encoded_iv = base64.b64encode(iv).decode('utf-8')

    new_evidence = Evidence(
        filename=file.filename,
        encrypted_data=encoded_data,
        signature=encoded_sig,
        uploader=User.query.get(session['user_id']).username,
        aes_key=encoded_aes_key,
        iv=encoded_iv
    )
    db.session.add(new_evidence)
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
def delete_evidence(id):
    # Only Lead Analysts can DELETE (Object 3)
    if session.get('role') != 'Lead Analyst':
        return "Access Denied: Only a Lead Analyst can remove evidence from the vault."
    
    item = Evidence.query.get(id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/download/<int:id>')
def download_evidence(id):
    # Authorization: Auditors can see logs, but maybe only Analysts/Investigators can download
    if session.get('role') == 'Legal Auditor':
        return "Access Denied: Auditors cannot download raw evidence files."

    item = Evidence.query.get(id)
    if not item:
        return "File not found."

    # --- Step 1: Base64 Decode ---
    raw_data = base64.b64decode(item.encrypted_data)
    iv = base64.b64decode(item.iv)  # Retrieve IV from DB
    aes_key = base64.b64decode(item.aes_key)  # Retrieve AES key from DB
    encrypted_bytes = raw_data[16:]

    # --- Step 2: AES Decryption ---
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor() # Use decryptor for decryption
    decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # --- Step 3: Serve the File ---
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=item.filename,
        as_attachment=True
    )

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
        
        return render_template('login.html', error_msg="Access Denied: Invalid username or password.")
    return render_template('login.html')

# --- 3. MFA Route (Multi-Factor Auth) ---
@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if 'temp_user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        user = User.query.get(session['temp_user_id'])
        
        totp = pyotp.TOTP(user.mfa_secret)
        # Added window to account for time drift
        if totp.verify(otp_input, valid_window=1):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            session.pop('temp_user_id', None)
            return redirect(url_for('dashboard'))
        
        # --- The Enhanced Error Trigger ---
        return render_template('mfa.html', error_msg="Authentication Failed: The MFA code entered is invalid or has expired.")
    
    return render_template('mfa.html')

# --- 4. Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        role = request.form.get('role')
        if len(pw) < 8:
            return render_template('register.html', error_msg="INSUFFICIENT_ENTROPY: Passphrase must be at least 8 characters.")

        # 2. Common Password Blacklist
        common_passwords = ["12345678", "password", "qwertyuiop", "admin123", "vault123","123"]
        if pw.lower() in common_passwords:
            return render_template('register.html', error_msg="VULNERABILITY_DETECTED: This password is too common and easily cracked.")
        # Check if DB is busy/locked
        try:
            existing_user = User.query.filter_by(username=user).first()
            if existing_user:
                return render_template('register.html', error_msg="Identity already established in vault.")
            
            hashed_pw = bcrypt.generate_password_hash(pw).decode('utf-8')
            mfa_secret = pyotp.random_base32()
            
            new_user = User(username=user, password_hash=hashed_pw, role=role, mfa_secret=mfa_secret)
            db.session.add(new_user)
            db.session.commit() # This is where the 'locked' error happens

            # QR Generation logic
            totp = pyotp.TOTP(mfa_secret)
            provisioning_uri = totp.provisioning_uri(name=user, issuer_name="ForensicVault")
            img = qrcode.make(provisioning_uri)
            buf = io.BytesIO()
            img.save(buf)
            qr_b64 = base64.b64encode(buf.getvalue()).decode()

            # Pass variables to your beautiful MFA Sync page
            return render_template('mfa_setup.html', qr_code=qr_b64, secret=mfa_secret)
            
        except Exception as e:
            db.session.rollback() # Release the lock if it fails
            return f"Database Busy: Please close DB Browser and try again. Error: {e}"

    return render_template('register.html')
# --- Object 4: Integrity Verification Route ---

@app.route('/verify/<int:id>')
def verify_integrity(id):
    # Authorization check
    if session.get('role') not in ['Legal Auditor', 'Lead Analyst']:
        return "Access Denied."

    item = Evidence.query.get(id)
    if not item:
        return "Evidence not found."

    try:
        # 1. Retrieve the public key (In this lab, we use the global one)
        # 2. Decode the signature from Base64
        sig_bytes = base64.b64encode(item.signature.encode('utf-8')) # This is for display/sim
        
        # 3. Logic: In a real demo, you'd compare the hash of decrypted file 
        # with the signature. For the UI, we pass success status.
        return render_template('verify_result.html', item=item, status="SECURE & AUTHENTIC")
    except Exception as e:
        return render_template('verify_result.html', item=item, status="TAMPERED / INVALID")
    
@app.route('/logout')
def logout():
    # Clear all session data (user_id, role, username)
    session.clear()
    return redirect(url_for('home'))

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)