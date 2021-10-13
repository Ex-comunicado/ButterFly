from flask import Flask, render_template, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:password@localhost/butterfly"
app.config['SECRET_KEY'] = 'bababooey'

db = SQLAlchemy(app)

#------------------DatabaseModels------------------
class Users(db.Model):
    id = db.Column(db.Integer(),primary_key=True)
    username = db.Column(db.String(length=30),nullable=False,unique=True)
    email = db.Column(db.String(length=50),nullable=False, unique=True)
    password = db.Column(db.String(length=60),nullable=False)
#------------------DatabaseModels------------------

#------------------Forms------------------
class RegisterForm(FlaskForm):    
    def validate_username(self, user_to_check):
        usercheck = Users.query.filter_by(username=user_to_check.data).first()
        if usercheck:
            raise ValidationError('Username Already exists.')
    
    def validate_email_addr(self, email_addr_to_check):
        emailcheck = Users.query.filter_by(email=email_addr_to_check.data).first()
        if emailcheck:
            raise ValidationError('Email Address already exists.')
    
    username = StringField("Username: ", validators=[DataRequired(), Length(min=2, max=30)])
    email_addr = StringField("E-mail Address: ", validators=[DataRequired(), Email()])
    password1 = PasswordField("Password: ", validators=[Length(min=6), DataRequired()]) 
    password2 = PasswordField("Confirm Password: ", validators=[EqualTo('password1'), DataRequired()])
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
    if form.validate_on_submit():
        user = Users(username=form.username.data,
                    email=form.email_addr.data,
                    password=form.password1.data
                    )
        db.session.add(user)
        db.session.commit()
        form.username.data = ''
        form.email_addr.data = ''
        form.password1.data = ''
        form.password2.data = ''
        login_user(user)
        flash(f'Accounted Created Successfully! You are now logged in as {user.username}', category="success")
        return redirect(url_for('home_page'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'Kindly review this error: {err_msg}', category='danger')
    return render_template('register.html', form=form)
#------------------Routes------------------