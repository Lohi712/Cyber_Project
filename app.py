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
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secure_vault_key"

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

# --- 1. User Model (Authentication & Hashing with Salt) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    mfa_secret = db.Column(db.String(32), nullable=False)
    security_question = db.Column(db.String(200))
    security_answer_hash = db.Column(db.String(128))

# --- Evidence Model (Encryption & Hashing) ---
class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    encrypted_data = db.Column(db.Text) 
    signature = db.Column(db.Text) 
    uploader = db.Column(db.String(50))
    aes_key = db.Column(db.String(44))
    iv = db.Column(db.String(24))
    is_verified = db.Column(db.Boolean, default=False) 
    verified_by = db.Column(db.String(50), nullable=True)
    verified_at = db.Column(db.DateTime, nullable=True)

# --- AccessLog Model (ONLY DEFINE ONCE!) ---
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    accessed_by = db.Column(db.String(50), nullable=False)
    access_type = db.Column(db.String(20), nullable=False)
    accessed_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# ============================================
# RSA KEY MANAGEMENT - FIXED VERSION
# ============================================
def load_or_generate_keys():
    """Load existing RSA keys or generate new ones if they don't exist."""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        # Load existing keys
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        print("[INFO] Loaded existing RSA keys from files.")
    else:
        # Generate new keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        # Save private key
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[INFO] Generated and saved new RSA keys.")
    
    return private_key, public_key

# IMPORTANT: Call the function and assign to global variables!
private_key, public_key = load_or_generate_keys()

# ============================================
# ROUTES
# ============================================

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    
    all_evidence = Evidence.query.all()
    return render_template('dashboard.html', user_role=session.get('role'), evidence=all_evidence)

@app.route('/upload', methods=['POST'])
def upload_file():
    if session.get('role') not in ['Lead Analyst', 'Investigator']:
        return "Access Denied: Your role does not permit uploading evidence."
    if session.get('role') == 'Legal Auditor':
        return "Access Denied: Auditors cannot upload evidence."

    file = request.files['evidence_file']
    if not file:
        return "No file selected."
    file_data = file.read()

    # --- 1. Encryption (AES-256 Symmetric) ---
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(file_data) + encryptor.finalize()

    # --- 2. Digital Signature (RSA + SHA-256) ---
    signature = private_key.sign(
        file_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # --- 3. Encoding (Base64) ---
    encoded_data = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
    encoded_sig = base64.b64encode(signature).decode('utf-8')
    encoded_aes_key = base64.b64encode(aes_key).decode('utf-8')
    encoded_iv = base64.b64encode(iv).decode('utf-8')

    new_evidence = Evidence(
        filename=file.filename,
        encrypted_data=encoded_data,
        signature=encoded_sig,
        uploader=session.get('username', 'Unknown'),
        aes_key=encoded_aes_key,
        iv=encoded_iv
    )
    db.session.add(new_evidence)
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:id>')
def delete_evidence(id):
    if session.get('role') != 'Lead Analyst':
        return "Access Denied: Only a Lead Analyst can remove evidence from the vault."
    
    item = Evidence.query.get(id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/download/<int:id>')
def download_evidence(id):
    if session.get('role') == 'Legal Auditor':
        return "Access Denied: Auditors cannot download raw evidence files."

    item = Evidence.query.get(id)
    if not item:
        return "File not found."
    
    if session.get('username') != item.uploader:
        access_log = AccessLog(
            evidence_id=id,
            accessed_by=session.get('username'),
            access_type='download'
        )
        db.session.add(access_log)
        db.session.commit()

    # --- Step 1: Base64 Decode ---
    raw_data = base64.b64decode(item.encrypted_data)
    iv = base64.b64decode(item.iv)
    aes_key = base64.b64decode(item.aes_key)
    encrypted_bytes = raw_data[16:]

    # --- Step 2: AES Decryption ---
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()

    # --- Step 3: Serve the File ---
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=item.filename,
        as_attachment=True
    )

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        user_input = request.form.get('username')
        pass_input = request.form.get('password')
        
        user = User.query.filter_by(username=user_input).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, pass_input):
            session['temp_user_id'] = user.id
            return redirect(url_for('mfa_verify'))
        
        return render_template('login.html', error_msg="Access Denied: Invalid username or password.")
    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa_verify():
    if 'temp_user_id' not in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        user = User.query.get(session['temp_user_id'])
        
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(otp_input, valid_window=1):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            session.pop('temp_user_id', None)
            return redirect(url_for('dashboard'))
        
        return render_template('mfa.html', error_msg="Authentication Failed: The MFA code entered is invalid or has expired.")
    
    return render_template('mfa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        role = request.form.get('role')
        q = request.form.get('security_question')
        a = request.form.get('security_answer')

        existing_user = User.query.filter_by(username=user).first()
        if existing_user:
            return render_template('register.html', error_msg="Duplicate Entity Detected.")
        
        if len(pw) < 8:
            return render_template('register.html', error_msg="Password too short (Min 8 chars).")

        hashed_pw = bcrypt.generate_password_hash(pw).decode('utf-8')
        a_hash = bcrypt.generate_password_hash(a.lower().strip()).decode('utf-8')
        mfa_secret = pyotp.random_base32()
        
        try:
            new_user = User(
                username=user, 
                password_hash=hashed_pw, 
                role=role, 
                mfa_secret=mfa_secret,
                security_question=q,
                security_answer_hash=a_hash
            )
            db.session.add(new_user)
            db.session.commit()

            totp = pyotp.TOTP(mfa_secret)
            provisioning_uri = totp.provisioning_uri(name=user, issuer_name="EvidenceVault")
            img = qrcode.make(provisioning_uri)
            buf = io.BytesIO()
            img.save(buf)
            qr_b64 = base64.b64encode(buf.getvalue()).decode()

            return render_template('mfa_setup.html', qr_code=qr_b64, secret=mfa_secret)
            
        except Exception as e:
            db.session.rollback()
            return render_template('register.html', error_msg="Database Error: Close DB Browser and try again.")

    return render_template('register.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        security_answer = request.form.get('security_answer')
        new_password = request.form.get('new_password')
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return render_template('reset.html', error_msg="IDENT_ID_NOT_FOUND")

        if not security_answer:
            return render_template('reset.html', 
                                   username=username, 
                                   security_question=user.security_question,
                                   show_question=True)

        provided_answer = security_answer.lower().strip()
        if not bcrypt.check_password_hash(user.security_answer_hash, provided_answer):
            return render_template('reset.html', 
                                   username=username,
                                   security_question=user.security_question,
                                   show_question=True,
                                   error_msg="RECOVERY_ANSWER_INVALID")
        
        if len(new_password) < 8:
            return render_template('reset.html', 
                                   username=username,
                                   security_question=user.security_question,
                                   show_question=True,
                                   error_msg="PASSPHRASE_TOO_SHORT (Min 8 chars)")

        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        
        return render_template('login.html', success_msg="PASSPHRASE_UPDATED: Login with new credentials")
        
    return render_template('reset.html')

@app.route('/access_log/<int:id>')
def view_access_log(id):
    item = Evidence.query.get(id)
    if not item:
        return "Evidence not found."
    
    if session.get('username') != item.uploader and session.get('role') != 'Lead Analyst':
        return "Access Denied: You can only view logs for your own uploads."
    
    logs = AccessLog.query.filter_by(evidence_id=id).order_by(AccessLog.accessed_at.desc()).all()
    return render_template('access_log.html', item=item, logs=logs)

@app.route('/verify/<int:id>')
def verify_integrity(id):
    if session.get('role') not in ['Legal Auditor', 'Lead Analyst']:
        return "Access Denied."

    item = Evidence.query.get(id)
    if not item:
        return "Evidence not found."

    try:
        aes_key = base64.b64decode(item.aes_key)
        iv = base64.b64decode(item.iv)
        raw_data = base64.b64decode(item.encrypted_data)
        
        encrypted_bytes = raw_data[16:]
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()

        signature_bytes = base64.b64decode(item.signature)
        
        public_key.verify(
            signature_bytes,
            decrypted_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        return render_template('verify_result.html', item=item, status="PASS", can_confirm=True)

    except Exception as e:
        return render_template('verify_result.html', item=item, status="FAIL", can_confirm=False)
    
@app.route('/confirm_verification/<int:id>', methods=['POST'])
def confirm_verification(id):
    if session.get('role') not in ['Legal Auditor', 'Lead Analyst']:
        return "Access Denied."
    
    item = Evidence.query.get(id)
    if not item:
        return "Evidence not found."
    
    item.is_verified = True
    item.verified_by = session.get('username')
    item.verified_at = datetime.now()
    db.session.commit()
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Initialize the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)