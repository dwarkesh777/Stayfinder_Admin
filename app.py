from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime
import os

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
        
        admin = admins_collection.find_one({'email': email})
        
        if admin and check_password_hash(admin['password'], password):
            session['admin_id'] = str(admin['_id'])
            session['admin_name'] = admin['name']
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid email or password', 'error')
    
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

if __name__ == '__main__':
    app.run(debug=True)
