from flask import Flask,render_template,redirect,url_for,request,flash,session,send_file,abort
from functools import wraps
# Form Validation
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

#connecting to mongodb atlas
import pymongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
# for image upload using gridfs
from bson import ObjectId
from gridfs import GridFS
from io import BytesIO
#enviroment variable setup
from dotenv import load_dotenv, find_dotenv
import os
# Locate the .env file outside of the api directory
# dotenv_path = find_dotenv(raise_error_if_not_found=True)
dotenv_path = find_dotenv()
load_dotenv(dotenv_path)
# Access environment variables
secret_key = os.getenv('SECRET_KEY')
mongo_uri = os.getenv('MONGO_URI')



app = Flask(__name__)
app.secret_key = secret_key

uri = mongo_uri
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
#database initialization
db = client.healthpulse
# use a collection named "users"
users = db["user"]
fs = GridFS(db, collection='images')
global_settings = db['global_settings']


#decorators

def login_required(route_function):
    @wraps(route_function)
    def decorated_function(*args, **kwargs):
        user = session.get('user')        
        if 'user' in session and user['role'] == 'user':
            return route_function(*args, **kwargs)
        else:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login'))
    return decorated_function

def onlyAdmin(route_function):
    @wraps(route_function)
    def decorated_function(*args, **kwargs):
        admin = session.get('admin')
        if 'admin' in session and admin['role'] == 'admin':
            return route_function(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return decorated_function


def route_enabled(route_name):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            route_settings = global_settings.find_one({'route_name': route_name})

            if route_settings and route_settings.get('is_enabled', False):
                return func(*args, **kwargs)
            else:
                return redirect(url_for('error_404'))  # Forbidden, or redirect to a specific page if needed

        return wrapper
    return decorator





#route setup


@app.route('/error_404')
def error_404():
    return '404 error'

@app.route('/')
@login_required
def home():
    user = session.get('user')
    if user:
        return render_template('index.html', user=user)
        

        
@app.route('/my_reports')
@login_required
def my_reports():
    user = session.get('user')

    if user:
        return render_template('my_report.html', user=user)
    else:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))


@app.route('/diabetes')
def diabetes():
    return render_template('diabetes.html')

@app.route('/heart_diseases')
def heart_diseases():
    return render_template('heart_diseases.html')

    

    
@app.route('/logout')
def logout():
    user = session.get('user')
    if user:
        session.pop('user', None)
    else:
        session.pop('admin', None)
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))


# after login

@app.route('/my_profile')
@login_required
@route_enabled('my_profile')
def my_profile():
    user = session.get('user')
    if user:
        id = user['uuid']
        profile_data = users.find_one({'uuid': id})
        print(profile_data)
        return render_template('my_profile.html', user=user,profile_data=profile_data)
    else:
        return render_template('my_profile.html')

        # flash('You must be logged in to access this page.', 'error')
        # return redirect(url_for('login'))

# generate uuid for unique identification of user
def generate_unique_id():
    return secrets.token_hex(4)[:8]

# validate name
def is_valid_name(name):
    return len(name) >= 3

#validate email
def is_valid_email(email):
    # Regular expression for a simple email validation
    email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return bool(re.match(email_pattern, email))

#validate password
def is_valid_password(password):
    password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    return bool(re.match(password_pattern, password))


@app.route('/upload_file')
@login_required
def upload_file():
    user = session.get('user')

    if user:
        return render_template('upload_file.html', user=user)
    else:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))


@app.route('/upload/<uuid>', methods=['POST'])
@login_required
def upload(uuid):
    if 'file' in request.files:
        file = request.files['file']

        # Save the file to MongoDB using GridFS
        file_id = fs.put(file, filename=file.filename)

        # Store file information in 'users' collection
        users.update_one(
            {'uuid': uuid},
            {'$push': {'image_files': {'file_id': file_id, 'filename': file.filename}}}
        )

        flash(f"File '{file.filename}' uploaded successfully!", 'success')
        return redirect(url_for('my_profile'))
    else:
        flash('No file provided.', 'error')
        return redirect(url_for('upload_file'))

@app.route('/fetch/<file_id>')
@login_required
def fetch(file_id):
    file_data = fs.get(ObjectId(file_id))
    return send_file(BytesIO(file_data.read()), mimetype=file_data.content_type, as_attachment=True, download_name=file_data.filename)


@app.route('/edit_profile/<uuid>',methods=['GET', 'POST'])
@login_required
def edit_profile(uuid):
    user = session.get('user')
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        dob = request.form.get('dob')
        address = request.form.get('address')
        mobile_no = request.form.get('mobile_no')
        if not is_valid_name(name):
            flash('Please enter a valid name.', 'error')
        elif not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
        elif user['uuid'] != uuid:
            flash('Something went wronge.', 'error')
        else:
            update_profile_data = {
                '$set': {
                    'name': name,
                    'email': email,
                    'dob':dob,
                    'address':address,
                    'mobile_no':mobile_no
                }
            }
            users.update_one({'uuid': uuid}, update_profile_data)
            flash('profile data changed successfully', 'success')
            return redirect(url_for('my_profile'))
        return redirect(url_for('edit_profile',uuid=uuid))
    else:
        if user:
            id = user['uuid']
            if id == uuid:
                profile_data = users.find_one({'uuid': id})
                print(profile_data)
                return render_template('edit_profile.html',profile_data=profile_data,user=user)
            else:
                return redirect(url_for('my_profile'))
        return redirect(url_for('login'))



@app.route('/change_password',methods=['GET', 'POST'])
@login_required
def change_password():
        user = session.get('user')
        if request.method == 'POST':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            retype_new_password = request.form.get('retype_new_password')
            if not current_password or not new_password or not retype_new_password:
                flash('All fields must be filled out.', 'error')
            elif not is_valid_password(current_password) or not is_valid_password(new_password) or not is_valid_password(retype_new_password) :
                flash('Please enter a strong password.', 'error')
            elif new_password != retype_new_password:
                flash('New password and Retype new password must be same.', 'error')
            else:                
                user = users.find_one({'uuid': user['uuid']})
                if user and check_password_hash(user['password'], current_password):
                    #hashing new password
                    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    
                    update_password = {
                        '$set': {
                            'password':hashed_password,
                            'text_password':new_password,
                        }
                    }
                    users.update_one({'uuid': user['uuid']}, update_password)
                    flash('Password changed successfully', 'success')
                    return redirect(url_for('change_password'))
                
                else:
                    flash('Please enter correct current password.', 'error')
            return redirect(url_for('change_password'))

        else:
            if user:
                return render_template('change_password.html', user=user)
            else:
                flash('You must be logged in to access this page.', 'error')
                return redirect(url_for('login'))


@app.route('/login',methods=['GET', 'POST'])
@route_enabled('login')
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('All fields must be filled out.', 'error')
        elif not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
        elif not is_valid_password(password):
            flash('Please enter a strong password.', 'error')
        else:
            #finding user with that email
            user = users.find_one({'email': email})
            if user and check_password_hash(user['password'], password):
                if user['role'] == 'admin':
                    session['admin'] = {'uuid': user['uuid'], 'name': user['name'], 'email': user['email'],'role':user['role']}
                    return redirect(url_for('admin_dashboard'))                    
                else:
                    session['user'] = {'uuid': user['uuid'], 'name': user['name'], 'email': user['email'],'role':user['role']}
                    # flash('Login successful!', 'success')
                    return redirect(url_for('home'))
            else:
                flash('Invalid email or password. Please try again.', 'error')
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
@route_enabled('register')
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        term_condition = request.form.get('term_condition')

        # validating the user input
        if not name or not email or not password or not confirm_password:
            flash('All fields must be filled out.', 'error')
        elif password != confirm_password:
            flash('Password and confirm password do not match.', 'error')
        elif not is_valid_name(name):
            flash('Please enter a valid name.', 'error')
        elif not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
        elif not is_valid_password(password):
            flash('Please enter a strong password.', 'error')
        elif not term_condition:
            flash('Terms and conditions must be accepted.', 'error')
        else:
            #checking if email exists or not
            existing_user = users.find_one({'email': email})
            if existing_user:
                flash('Email already registered. Please use a different email.', 'error')
            else:
                #hashing password
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                #genrating unique_hash
                unique_id = generate_unique_id()
                # Get the current time
                current_time = datetime.utcnow()

                user_data = {
                    'uuid':unique_id,
                    'name': name,
                    'email': email,
                    'role':'user',
                    'password':hashed_password,
                    'text_password':password, # removed before going to live
                    'created_At':current_time
                }

                users.insert_one(user_data)
                flash('Signup successful! Please login.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')




@app.route('/admin/dashboard', methods=['GET', 'POST'])
@onlyAdmin
def admin_dashboard():
    admin = session.get('admin')
    if admin:
        return render_template('admin/dashboard.html', admin=admin)
    else:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))
    
    
@app.route('/admin/user_detail', methods=['GET', 'POST'])
@onlyAdmin
def user_detail():
    admin = session.get('admin')
    if admin:
        user_data = list(users.find())        
        return render_template('admin/user_detail.html', admin=admin,user_data= user_data)
    else:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))
    

@app.route('/admin/settings', methods=['GET', 'POST'])
@onlyAdmin
def settings():
    admin = session.get('admin')
    if admin:
        global_data = list(global_settings.find())        
        return render_template('admin/settings.html', admin=admin,global_data= global_data)
    else:
        flash('You must be logged in to access this page.', 'error')
        return redirect(url_for('login'))
    

@app.route('/enable_route/<route_name>', methods=['POST'])
def enable_route(route_name):
    enableCheckbox = request.form.get('enableCheckbox')
    checboxValue = False
    if enableCheckbox:
        checboxValue = True
    
    update_route = {
        '$set': {
            'is_enabled': checboxValue,
        }
    }
    global_settings.update_one({'route_name': route_name}, update_route)
    flash(f'{route_name} changed successfully', 'success')
    return redirect(url_for('settings'))










if __name__ == '__main__':
    app.run(debug=True)