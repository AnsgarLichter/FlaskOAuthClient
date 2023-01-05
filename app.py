import datetime
from flask import Flask, render_template, request, redirect, url_for

# Flask Login
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user

# SQLAlchemy
from flask_sqlalchemy import SQLAlchemy

# Forms
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

# Password Hash
from flask_bcrypt import Bcrypt

# Environemnt Variables
from os import getenv

import requests


# OAuth
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session

# Create Application
app = Flask(__name__)


# App Config
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SECRET_KEY"] = "secret"


# OAuth
oauth = OAuth(app)

github = oauth.register(
    name='github',
    client_id=getenv("GITHUB_CLIENT_ID"),
    client_secret=getenv("GITHUB_SECRET_ID"),
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'read:user'},
)

own_server = oauth.register(
    name='own',
    client_id='y0tvY0Pmxjt67ILUT9pGaXuh',
    client_secret='FtIDRex3sFKWKXGVgSBpWZvkuXI27UQiFX4VuD7AItgS0AWK',
    access_token_url='http://127.0.0.1:5002/oauth/token',
    access_token_params=None,
    authorize_url='http://127.0.0.1:5002/oauth/authorize',
    api_base_url='http://127.0.0.1:5002/'
)

kadi_server = oauth.register(
    name='kadi',
    client_id=getenv('KADI_CLIENT_ID'),
    client_secret=getenv('KADI_SECRET_ID'),
    access_token_url='http://localhost:5000/oauth2server/oauth/access_token',
    access_token_params=None,
    authorize_url='http://localhost:5000/oauth2server/oauth/authorize',
    api_base_url='http://localhost:5000/'
)

# Initialize Dependencies
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# Provide User Loader Callback for Login Manager of Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Flask-Login has the requirement that an user class is implemented
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=True)
    access_token = db.Column(db.String(100), nullable=True)
    refresh_token = db.Column(db.String(100), nullable=True)


# Sign Up Form
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
            raise ValidationError(
                "That username already exists! Please choose a different one")


# Login Form
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


# Actual views / route definitions of the application
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

    return redirect(url_for("welcome"))


@app.route("/login/github")
def login_github():
    github = oauth.create_client("github")

    redirect_url = url_for("authorize_github", _external=True)

    return github.authorize_redirect(redirect_url)


@app.route("/login/github/authorize")
def authorize_github():
    github = oauth.create_client("github")

    token = github.authorize_access_token()
    print(f"\nToken: {token}\n")

    # Load users data
    url = 'https://api.github.com/user'
    access_token = "token " + token["access_token"]
    headers = {"Authorization": access_token}

    resp = requests.get(url=url, headers=headers)

    user_data = resp.json()
    user_name = user_data["login"]
    print(f"\nUsername: {user_name}\n")

    existing_user = User.query.filter_by(
        username=user_name).first()
    if existing_user:
        existing_user.access_token = access_token
        db.session.commit()

        login_user(existing_user)

        return redirect(url_for("protected"))

    new_user = User(username=user_name, access_token=token["access_token"])

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)

    return redirect(url_for("protected"))


@app.route("/login/own")
def login_own():
    own = oauth.create_client("own")

    redirect_url = url_for("authorize_own", _external=True)
    return own.authorize_redirect(redirect_url)


@app.route("/login/own/authorize")
def authorize_own():
    own = oauth.create_client("own")

    token = own.authorize_access_token()
    print(f"\nToken: {token}\n")

    # Load users data
    url = 'http://127.0.0.1:5002/api/me'
    access_token = "Bearer " + token["access_token"]
    headers = {"Authorization": access_token}

    resp = requests.get(url=url, headers=headers)

    user_data = resp.json()
    user_name = user_data["username"]
    print(f"\nUsername: {user_name}\n")

    existing_user = User.query.filter_by(
        username=user_name).first()
    if existing_user:
        existing_user.access_token = access_token
        db.session.commit()

        login_user(existing_user)

        return redirect(url_for("protected"))

    new_user = User(username=user_name, access_token=token["access_token"])

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)

    return redirect(url_for("protected"))


@app.route("/login/kadi")
def login_kadi():
    kadi = oauth.create_client("kadi")

    redirect_url = "http://127.0.0.1:5001/login/kadi/authorize"

    return kadi.authorize_redirect(redirect_url)


@app.route("/login/kadi/authorize")
def authorize_kadi():
    kadi = oauth.create_client("kadi")

    token = kadi.authorize_access_token()
    print(f"\nToken: {token}\n")
    kadi.token = token

    expires_at = token["expires_at"]
    print(f"\nToken expires at: {expires_at}\n")
    expires_at_date = datetime.datetime.fromtimestamp(expires_at)
    print(f"\n Expires at date: {expires_at_date}")

    user_name = "admin"
    existing_user = User.query.filter_by(
        username=user_name).first()
    if existing_user:
        existing_user.access_token = token["access_token"]
        existing_user.refresh_token = token["refresh_token"]
        db.session.commit()

        login_user(existing_user)

        return redirect(url_for("protected"))

    new_user = User(username=user_name,
                    access_token=token["access_token"], refresh_token=token["refresh_token"])

    db.session.add(new_user)
    db.session.commit()

    login_user(new_user)

    return redirect(url_for("protected"))


@app.route("/protected")
@login_required
def protected():
    return render_template("protected.html")


@app.route("/kadi/revoke/access_token")
@login_required
def revoke_kadi_access_token():
    client = OAuth2Session(
        getenv('KADI_CLIENT_ID'),
        getenv('KADI_SECRET_ID'),
    )

    headers = {"Authorization": "Bearer " + current_user.access_token}

    client.revoke_token(
        "http://localhost:5000/oauth2server/oauth/token/revoke",
        token=current_user.access_token,
        token_type_hint="access_token",
        headers=headers
    )

    return redirect(url_for("protected"))


@app.route("/kadi/revoke/refresh_token")
@login_required
def revoke_kadi_refresh_token():
    client = OAuth2Session(
        getenv('KADI_CLIENT_ID'),
        getenv('KADI_SECRET_ID'),
    )

    headers = {"Authorization": "Bearer " + current_user.access_token}

    client.revoke_token(
        "http://localhost:5000/oauth2server/oauth/token/revoke",
        token=current_user.refresh_token,
        token_type_hint="refresh_token",
        headers=headers
    )

    return redirect(url_for("protected"))


@app.route("/refresh")
@login_required
def refresh_kadi_access_token():
    client = OAuth2Session(
        getenv('KADI_CLIENT_ID'),
        getenv('KADI_SECRET_ID'),
    )

    new_access_token = client.refresh_token(
        url="http://localhost:5000/oauth2server/oauth/access_token/refresh",
        refresh_token=current_user.refresh_token
    )

    print(f"New access token {new_access_token}")

    current_user.access_token = new_access_token["access_token"]
    current_user.refresh_token = new_access_token["refresh_token"]
    db.session.commit()

    return redirect(url_for("protected"))


@app.route("/load_records")
@login_required
def load_records():
    url = 'http://localhost:5000/api/records'
    access_token = "Bearer " + current_user.access_token
    headers = {"Authorization": access_token}

    resp = requests.get(url=url, headers=headers)
    print(resp.json())

    return redirect(url_for("protected"))
