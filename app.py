from flask import Flask, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False

#------------------Forms------------------
class RegisterForm(FlaskForm):    
    username = StringField("Username: ")
    email_addr = StringField("E-mail Address: ")
    password1 = PasswordField("Password: ") 
    password2 = PasswordField("Confirm Password: ")
    submit = SubmitField("Create Account")

class LoginForm(FlaskForm):
    username = StringField("Username: ")
    password = PasswordField("Password: ")
    submit = SubmitField("Login")
#------------------Forms------------------

#------------------Routes------------------
@app.route('/')
def home_page():
    return render_template('home.html')

@app.route('/aboutus')
def about_us():
    return render_template('aboutus.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    return render_template('register.html', form=form)
#------------------Routes------------------