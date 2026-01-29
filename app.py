from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
import random
import string
import smtplib
import io
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Load .env File
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'stayfinder-secret-key')

# MongoDB Connection
MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    raise Exception("MONGO_URI not found in .env file!")

print(f"Connecting to MongoDB...")
client = MongoClient(MONGO_URI)

# Test connection
try:
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    raise e

db = client['stayfinder']
admins_collection = db['admins']
hostels_collection = db['hostels']
ratings_collection = db['ratings']
users_collection = db['users']
otp_collection = db['otp_requests']

# Email configuration
SMTP_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('MAIL_PORT', 587))
SENDER_EMAIL = os.getenv('MAIL_USERNAME')
SENDER_PASSWORD = os.getenv('MAIL_PASSWORD')

def send_otp_email(recipient_email, otp_code):
    """Send OTP to email"""
    try:
        subject = "StayFinder Admin - OTP Verification"
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>OTP Verification</h2>
                <p>Your OTP code is: <strong style="font-size: 24px; color: #667eea;">{otp_code}</strong></p>
                <p>This code will expire in 10 minutes.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
        </html>
        """
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()
        
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))


def send_email_with_attachment(recipient_email, subject, html_body, attachment_bytes, filename):
    """Send an HTML email with a PDF attachment (bytes)"""
    try:
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email

        # Attach HTML body
        body_part = MIMEText(html_body, 'html')
        msg.attach(body_part)

        # Attachment
        part = MIMEBase('application', 'pdf')
        part.set_payload(attachment_bytes)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
        msg.attach(part)

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email with attachment: {e}")
        return False

# Auth decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def guest_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' in session:
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
@guest_required
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        admin_key = request.form.get('admin_key')
        
        admin = admins_collection.find_one({'email': email})
        
        if admin and check_password_hash(admin['password'], password) and check_password_hash(admin.get('admin_key', ''), admin_key):
            session['admin_id'] = str(admin['_id'])
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid email, password, or admin key', 'error')
    
    return render_template('login.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
@guest_required
def admin_signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        if admins_collection.find_one({'email': email}):
            flash('Email already registered', 'error')
            return render_template('signup.html')
        
        hashed_password = generate_password_hash(password)
        
        admin = {
            'name': name,
            'email': email,
            'password': hashed_password,
            'role': 'admin',
            'created_at': datetime.now()
        }
        
        result = admins_collection.insert_one(admin)
        session['admin_id'] = str(result.inserted_id)
        session['admin_name'] = name
        
        return redirect(url_for('admin_dashboard'))
    
    return render_template('signup.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
    properties_count = hostels_collection.count_documents({})
    users_count = admins_collection.count_documents({})
    return render_template('dashboard.html', admin=admin, properties_count=properties_count, users_count=users_count)

@app.route('/admin/properties')
@login_required
def admin_properties():
    admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
    properties = list(hostels_collection.find())
    
    # Fetch ratings for each property
    for prop in properties:
        hostel_id = prop.get('_id')
        # Get all ratings for this hostel
        hostel_ratings = list(ratings_collection.find({'$or': [{'hostelId': hostel_id}, {'hostelId': str(hostel_id)}]}))
        if hostel_ratings:
            total_rating = sum(r.get('rating', 0) for r in hostel_ratings)
            prop['avgRating'] = round(total_rating / len(hostel_ratings), 1)
            prop['reviewCount'] = len(hostel_ratings)
        else:
            prop['avgRating'] = 0
            prop['reviewCount'] = 0
        # expose string id for use in templates/JS
        try:
            prop['id'] = str(hostel_id)
        except Exception:
            prop['id'] = ''
        # Set default status if not present
        if 'status' not in prop:
            prop['status'] = 'pending'
    
    return render_template('properties.html', admin=admin, properties=properties)


@app.route('/admin/download-properties-pdf', methods=['POST'])
@login_required
def download_properties_pdf():
    """Generate a PDF of all properties, email it to admin, and return it for download."""
    try:
        admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
        properties = list(hostels_collection.find())

        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        y = height - 72

        c.setFont("Helvetica-Bold", 16)
        c.drawString(72, y, "StayFinder - All Properties Report")
        y -= 30
        c.setFont("Helvetica", 10)

        for prop in properties:
            name = prop.get('name', 'Unnamed')
            location = prop.get('location') or prop.get('address') or ''
            price = prop.get('price') or prop.get('rent') or ''
            status = prop.get('status', '')
            ptype = prop.get('type', '')
            gender = prop.get('gender', '')
            amenities = prop.get('amenities', [])
            if isinstance(amenities, list):
                amenities = ', '.join(amenities[:10])
            lines = [
                f"Name: {name}",
                f"Location: {location}",
                f"Price: {price}",
                f"Type: {ptype}",
                f"Gender: {gender}",
                f"Status: {status}",
                f"Amenities: {amenities}",
                "--------------------------------------------------------------------------------",
            ]

            for line in lines:
                c.drawString(72, y, str(line))
                y -= 14
                if y < 72:
                    c.showPage()
                    y = height - 72
                    c.setFont("Helvetica", 10)

        c.save()
        buffer.seek(0)
        pdf_bytes = buffer.getvalue()

        # Email to admin (if configured)
        admin_email = admin.get('email') if admin and admin.get('email') else SENDER_EMAIL
        subject = 'StayFinder - Properties Report'
        html_body = f"<p>Hi {admin.get('name', 'Admin')},</p><p>Attached is the properties report (PDF).</p>"
        email_sent = False
        try:
            email_sent = send_email_with_attachment(admin_email, subject, html_body, pdf_bytes, 'properties_report.pdf')
            print(f"[DEBUG] Email sent status: {email_sent} to {admin_email}")
        except Exception as e:
            print(f"[DEBUG] Error while attempting to send email: {e}")

        # Return PDF for download
        return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name='properties_report.pdf')
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('admin_properties'))


@app.route('/admin/users')
@login_required
def admin_users():
    try:
        admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
        # Fetch only owners from users collection
        owners = list(users_collection.find({'user_type': 'owner'}))

        # Normalize owner records for template
        for owner in owners:
            try:
                owner['id'] = str(owner.get('_id'))
            except Exception:
                owner['id'] = ''
            # provide some safe defaults
            owner['name'] = owner.get('name') or owner.get('full_name') or 'Unnamed'
            owner['email'] = owner.get('email', 'N/A')
            owner['phone'] = owner.get('phone', owner.get('mobile', 'N/A'))
            owner['created_at'] = owner.get('created_at', '')

        return render_template('users.html', admin=admin, owners=owners)
    except Exception as e:
        flash(f'Error fetching users: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/settings')
@login_required
def admin_settings():
    admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
    return render_template('settings.html', admin=admin)

@app.route('/admin/settings/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        
        if not name or not email:
            flash('Name and email are required', 'error')
            return render_template('edit_profile.html', admin=admin)
        
        # Check if email is already used by another admin
        existing_admin = admins_collection.find_one({'email': email, '_id': {'$ne': ObjectId(session['admin_id'])}})
        if existing_admin:
            flash('Email already registered by another account', 'error')
            return render_template('edit_profile.html', admin=admin)
        
        try:
            admins_collection.update_one(
                {'_id': ObjectId(session['admin_id'])},
                {'$set': {'name': name, 'email': email, 'updated_at': datetime.now()}}
            )
            session['admin_name'] = name
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('admin_settings'))
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'error')
    
    return render_template('edit_profile.html', admin=admin)

@app.route('/admin/property/<hostel_id>/view')
@login_required
def view_property(hostel_id):
    try:
        hostel_id_obj = ObjectId(hostel_id)
        property_data = hostels_collection.find_one({'_id': hostel_id_obj})
        
        if property_data:
            # Fetch ratings for this property
            hostel_ratings = list(ratings_collection.find({'$or': [{'hostelId': hostel_id_obj}, {'hostelId': str(hostel_id_obj)}]}))
            if hostel_ratings:
                total_rating = sum(r.get('rating', 0) for r in hostel_ratings)
                property_data['avgRating'] = round(total_rating / len(hostel_ratings), 1)
                property_data['reviewCount'] = len(hostel_ratings)
                property_data['allReviews'] = hostel_ratings
            else:
                property_data['avgRating'] = 0
                property_data['reviewCount'] = 0
                property_data['allReviews'] = []
            
            # Expose string id for templates
            property_data['id'] = str(hostel_id_obj)
            
            admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
            return render_template('property_detail.html', admin=admin, property=property_data)
        else:
            flash('Property not found', 'error')
            return redirect(url_for('admin_properties'))
    except Exception as e:
        flash(f'Error fetching property: {str(e)}', 'error')
        return redirect(url_for('admin_properties'))

@app.route('/api/ratings/<hostel_id>')
def api_ratings(hostel_id):
    # return average rating and count for requested hostel id
    query_options = []
    try:
        oid = ObjectId(hostel_id)
        query_options.append({'hostelId': oid})
    except Exception:
        oid = None
    query_options.append({'hostelId': hostel_id})

    hostel_ratings = list(ratings_collection.find({'$or': query_options}))
    if hostel_ratings:
        total = sum(r.get('rating', 0) for r in hostel_ratings)
        avg = round(total / len(hostel_ratings), 1)
        count = len(hostel_ratings)
    else:
        avg = 0
        count = 0
    return {'avg': avg, 'count': count}

@app.route('/admin/property/<hostel_id>/approve', methods=['POST'])
@login_required
def approve_property(hostel_id):
    try:
        hostel_id_obj = ObjectId(hostel_id)
        hostels_collection.update_one({'_id': hostel_id_obj}, {'$set': {'status': 'approved', 'updated_at': datetime.now()}})
        flash(f'Property approved successfully!', 'success')
    except Exception as e:
        flash(f'Error approving property: {str(e)}', 'error')
    return redirect(url_for('admin_properties'))

@app.route('/admin/property/<hostel_id>/reject', methods=['POST'])
@login_required
def reject_property(hostel_id):
    try:
        hostel_id_obj = ObjectId(hostel_id)
        hostels_collection.update_one({'_id': hostel_id_obj}, {'$set': {'status': 'rejected', 'updated_at': datetime.now()}})
        flash(f'Property rejected successfully!', 'error')
    except Exception as e:
        flash(f'Error rejecting property: {str(e)}', 'error')
    return redirect(url_for('admin_properties'))

@app.route('/admin/change-password', methods=['GET', 'POST'])
@login_required
def change_password_request():
    if request.method == 'POST':
        admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
        
        otp_code = generate_otp()
        admin_id = str(session['admin_id'])
        
        print(f"[DEBUG] Generating OTP for admin_id: {admin_id}")
        print(f"[DEBUG] OTP Code: {otp_code}")
        
        # Delete any existing OTP for this admin first
        otp_collection.delete_many({'admin_id': admin_id, 'purpose': 'change_password'})
        
        otp_result = otp_collection.insert_one({
            'admin_id': admin_id,
            'otp': otp_code,
            'purpose': 'change_password',
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(minutes=15)
        })
        
        print(f"[DEBUG] OTP inserted with ID: {otp_result.inserted_id}")
        
        if send_otp_email(admin['email'], otp_code):
            flash('OTP sent to your email', 'success')
            session['otp_purpose'] = 'change_password'
            return redirect(url_for('verify_otp'))
        else:
            flash('Error sending OTP. Please try again.', 'error')
    
    return render_template('change_password_request.html')

@app.route('/admin/update-admin-key', methods=['GET', 'POST'])
@login_required
def update_admin_key_request():
    if request.method == 'POST':
        admin = admins_collection.find_one({'_id': ObjectId(session['admin_id'])})
        
        otp_code = generate_otp()
        admin_id = str(session['admin_id'])
        
        print(f"[DEBUG] Generating OTP for admin_id: {admin_id}")
        print(f"[DEBUG] OTP Code: {otp_code}")
        
        # Delete any existing OTP for this admin first
        otp_collection.delete_many({'admin_id': admin_id, 'purpose': 'update_admin_key'})
        
        otp_result = otp_collection.insert_one({
            'admin_id': admin_id,
            'otp': otp_code,
            'purpose': 'update_admin_key',
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(minutes=15)
        })
        
        print(f"[DEBUG] OTP inserted with ID: {otp_result.inserted_id}")
        
        if send_otp_email(admin['email'], otp_code):
            flash('OTP sent to your email', 'success')
            session['otp_purpose'] = 'update_admin_key'
            return redirect(url_for('verify_otp'))
        else:
            flash('Error sending OTP. Please try again.', 'error')
    
    return render_template('update_admin_key_request.html')

@app.route('/admin/verify-otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        purpose = session.get('otp_purpose')
        admin_id = str(session['admin_id'])
        
        if not purpose:
            flash('Session expired. Please try again.', 'error')
            return redirect(url_for('admin_settings'))
        
        # Find OTP record
        otp_doc = otp_collection.find_one({
            'admin_id': admin_id,
            'purpose': purpose
        })
        
        print(f"[DEBUG] Looking for OTP: admin_id={admin_id}, purpose={purpose}")
        print(f"[DEBUG] Stored OTP doc: {otp_doc}")
        print(f"[DEBUG] User input OTP: {otp_input}")
        
        if otp_doc:
            stored_otp = str(otp_doc.get('otp', '')).strip()
            expires_at = otp_doc.get('expires_at')
            current_time = datetime.now()
            
            print(f"[DEBUG] Stored OTP: '{stored_otp}', User input: '{otp_input}'")
            print(f"[DEBUG] Expires at: {expires_at}, Current time: {current_time}")
            print(f"[DEBUG] OTP match: {stored_otp == otp_input}, Not expired: {expires_at and expires_at > current_time}")
            
            # Check if OTP matches and hasn't expired
            if stored_otp == otp_input and expires_at and expires_at > current_time:
                otp_collection.delete_one({'_id': otp_doc['_id']})
                session['otp_verified'] = True
                flash('OTP verified successfully!', 'success')
                
                if purpose == 'change_password':
                    return redirect(url_for('change_password_confirm'))
                elif purpose == 'update_admin_key':
                    return redirect(url_for('update_admin_key_confirm'))
            elif expires_at and expires_at <= current_time:
                otp_collection.delete_one({'_id': otp_doc['_id']})
                flash('OTP has expired. Please request a new one.', 'error')
                return redirect(url_for('admin_settings'))
            else:
                flash('Invalid OTP. Please check and try again.', 'error')
        else:
            print(f"[DEBUG] No OTP document found for admin_id={admin_id}, purpose={purpose}")
            flash('No OTP request found. Please request a new one.', 'error')
            return redirect(url_for('admin_settings'))
    
    purpose = session.get('otp_purpose', 'unknown')
    return render_template('verify_otp.html', purpose=purpose)

@app.route('/admin/change-password-confirm', methods=['GET', 'POST'])
@login_required
def change_password_confirm():
    if not session.get('otp_verified'):
        return redirect(url_for('change_password_request'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('change_password_confirm.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('change_password_confirm.html')
        
        hashed_password = generate_password_hash(new_password)
        admins_collection.update_one(
            {'_id': ObjectId(session['admin_id'])},
            {'$set': {'password': hashed_password, 'updated_at': datetime.now()}}
        )
        
        session.pop('otp_verified', None)
        session.pop('otp_purpose', None)
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_settings'))
    
    return render_template('change_password_confirm.html')

@app.route('/admin/update-admin-key-confirm', methods=['GET', 'POST'])
@login_required
def update_admin_key_confirm():
    if not session.get('otp_verified'):
        return redirect(url_for('update_admin_key_request'))
    
    if request.method == 'POST':
        new_admin_key = request.form.get('new_admin_key')
        confirm_admin_key = request.form.get('confirm_admin_key')
        
        if new_admin_key != confirm_admin_key:
            flash('Admin keys do not match', 'error')
            return render_template('update_admin_key_confirm.html')
        
        if len(new_admin_key) < 6:
            flash('Admin key must be at least 6 characters', 'error')
            return render_template('update_admin_key_confirm.html')
        
        hashed_admin_key = generate_password_hash(new_admin_key)
        admins_collection.update_one(
            {'_id': ObjectId(session['admin_id'])},
            {'$set': {'admin_key': hashed_admin_key, 'updated_at': datetime.now()}}
        )
        
        session.pop('otp_verified', None)
        session.pop('otp_purpose', None)
        flash('Admin key updated successfully!', 'success')
        return redirect(url_for('admin_settings'))
    
    return render_template('update_admin_key_confirm.html')

if __name__ == '__main__':
    app.run(debug=True)
