import bcrypt
from flask import Flask, render_template, request, redirect, url_for

##Flask Login
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user

##SQLAlchemy
from flask_sqlalchemy import SQLAlchemy

##Forms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

##Password Hash
from flask_bcrypt import Bcrypt


## Create Application
app = Flask(__name__)


##App Config
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "secret"


##Initialize Dependencies
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


## Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


## Provide User Loader Callback for Login Manager of Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


## Flaks-Login has the requirement that an user class is implemented
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


##Sign Up Form
class SignUpForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), 
        Length(min=4, max=20),
        ],
        render_kw={"placeholder": "Username"})
        
    password = PasswordField(validators=[
        InputRequired(), 
        Length(min=4, max=20),
        ],
        render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError("That username already exists! Please choose a different one")


##Login Form
class LoginForm(FlaskForm):
    username = StringField(validators=[
        InputRequired(), 
        Length(min=4, max=20),
        ],
        render_kw={"placeholder": "Username"})
        
    password = PasswordField(validators=[
        InputRequired(), 
        Length(min=4, max=20),
        ],
        render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")
    

##Actual views / route definitions of the application
@app.route("/")
def welcome(): 
    return render_template("main.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignUpForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

        
    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)

                return redirect(url_for("protected"))

    return render_template("login.html", form=form)

@app.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()
    
    return redirect(url_for("login"))

@app.route("/protected")
@login_required
def protected():
    return render_template("protected.html")