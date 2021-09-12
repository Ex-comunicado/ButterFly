from flask import Flask, render_template

app = Flask(__name__)

#------------------Routes------------------
@app.route('/')
def home_page():
    return render_template('home.html')

@app.route('/aboutus')
def about_us():
    return render_template('aboutus.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')
#------------------Routes------------------

#------------------Forms------------------
# Add form code here
#------------------Forms------------------