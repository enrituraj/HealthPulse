from flask import Flask,render_template,redirect,url_for,request,flash,session

# Form Validation
import secrets
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

#connecting to mongodb atlas
import pymongo
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
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
# use a collection named "recipes"
users = db["user"]




#route setup



@app.route('/')
def home():
        user = session.get('user')

        if user:
            return render_template('index.html', user=user)
        else:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login'))
        

@app.route('/diabetes')
def diabetes():
    return render_template('diabetes.html')

@app.route('/heart_diseases')
def heart_diseases():
    return render_template('heart_diseases.html')

    
@app.route('/brain_tumor')
def brain_tumor():
    return render_template('brain_tumor.html')

    
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logout successful!', 'success')
    return redirect(url_for('login'))


# after login

@app.route('/my_profile')
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




@app.route('/edit_profile/<uuid>',methods=['GET', 'POST'])
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
                session['user'] = {'uuid': user['uuid'], 'name': user['name'], 'email': user['email']}
                # flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password. Please try again.', 'error')
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
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
                    'password':hashed_password,
                    'text_password':password, # removed before going to live
                    'created_At':current_time
                }

                users.insert_one(user_data)
                flash('Signup successful! Please login.', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True)