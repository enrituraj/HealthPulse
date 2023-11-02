from flask import Flask,render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/diabetes')
def diabetes():
    return render_template('diabetes.html')

@app.route('/heart_diseases')
def heart_diseases():
    return render_template('heart_diseases.html')

    
@app.route('/brain_tumor')
def brain_tumor():
    return render_template('brain_tumor.html')

    
@app.route('/login')
def login():
    return render_template('login.html')
    
@app.route('/register')
def register():
    return render_template('register.html')




if __name__ == '__main__':
    app.run(debug=True)

