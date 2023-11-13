from flask import Flask,render_template,redirect,url_for,request,flash,session
from flask_pymongo import PyMongo

app = Flask(__name__)
app.secret_key = 'my_secret_key'

#connecting to database
try:
    app.config["MONGO_URI"] = "mongodb://localhost:27017/myDatabase"
    mongo = PyMongo(app)
    print("Connected to MongoDB successfully!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")


@app.route('/')
def home():
    # mongo.db.inventory.insert_one({"a":1,"b":2})
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

    
@app.route('/login',methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = mongo.db.users.find_one({'email': email})
        if user and user['password']== password:
            session['user'] = {'id': str(user['_id']), 'name': user['name'], 'email': user['email']}
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

        existing_user = mongo.db.users.find_one({'email': email})

        if existing_user:
            flash('Email already registered. Please use a different email.', 'error')
        else:
            user_data = {'name': name, 'email': email}
            mongo.db.users.insert_one(user_data)
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        
    return render_template('register.html')

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
        id = user['email']
        profile_data = mongo.db.users.find_one({'email': id})
        print(profile_data)
        return render_template('my_profile.html', user=user,profile_data=profile_data)
    else:
        return render_template('my_profile.html',profile_data={})

        # flash('You must be logged in to access this page.', 'error')
        # return redirect(url_for('login'))
        





if __name__ == '__main__':
    app.run(debug=True)

