from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from functools import wraps
from dotenv import load_dotenv
from datetime import datetime
import os

# Load .env file
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
    
    return render_template('properties.html', admin=admin, properties=properties)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


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

if __name__ == '__main__':
    app.run(debug=True)
