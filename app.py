from datetime import datetime, timedelta
import json
import secrets
import base64
import io
import pyotp
import qrcode
from flask import Flask, render_template, url_for, redirect, flash, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_oauthlib.client import OAuth

# Initialize Flask and its extensions
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
oauth = OAuth(app)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Load OAuth details
with open('config.json', 'r') as f:
    config = json.load(f)
google_client_id = config['Google']['CLIENT_ID']
google_client_secret = config['Google']['CLIENT_SECRET']


# Configure Google OAuth2
google = oauth.remote_app(
    'google',
    consumer_key=google_client_id,
    consumer_secret=google_client_secret,
    request_token_params={'scope': 'email profile'},
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


# Loading the user from the database by user ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Function to load a user from the database by their user ID

# Defining the User model for database representation
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=True, unique=True)
    password = db.Column(db.String(60), nullable=True)
    secret = db.Column(db.String(32), nullable=False)
    fa_enabled = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(255), unique=True, nullable=True)
    oauthProvider = db.Column(db.String(20), nullable=True)
    googleID = db.Column(db.String(21), nullable=True)
    name = db.Column(db.String(100), nullable=True)
    locked = db.Column(db.Boolean, default=False)
    lockedUntil = db.Column(db.DateTime, default=None, nullable=True)
    failedLogin = db.Column(db.Integer, default=0)
    # Defining the User class that represents a user in the database

# Defining the form for user registration
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')
    # Creating a registration form using Flask-WTF and WTForms library

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
        # Custom validation to check if the username is already in use

# Defining the form for user login
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')
    # Creating a login form using Flask-WTF and WTForms library

# Route for the home page
@app.route('/')
def home():
    return render_template('home.html')
# A route for the home page, rendering an HTML template

@app.route('/google_login')
def google_login():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/authorized')
def authorized():
    resp = google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['google_token'] = (resp['access_token'], '')
    me = google.get('userinfo')
    user_info = me.data

    user_email = user_info.get('email')
    user_name = user_info.get('name')  # Use .get() to avoid KeyError
    googleID = user_info.get('id')
    if user_name is None:
        user_name = user_email.split('@')[0]  # Use email prefix as a fallback


    # Generate a random secret for the user
    secret = pyotp.random_base32()
    # Check if user exists, if not then create
    existing_user = User.query.filter_by(email=user_email).first()
    if existing_user is None:
        new_user = User(
            email=user_email,
            name=user_name,
            googleID=googleID,
            oauthProvider='google',
            fa_enabled=1,
            secret=secret  # Set the generated secret here
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
    else:
        # Update the secret for existing user (Optional, based on your requirement
        existing_user.name = user_name
        existing_user.fa_enabled = 1
        db.session.commit()
        login_user(existing_user)

    return redirect(url_for('dashboard'))




@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

# Route for user login with rate limiting
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    form = LoginForm()
    if 'oauth' in request.args and request.args['oauth'] == 'true':
        return google.authorize(callback=url_for('authorized', _external=True))

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        # Check if user exists
        if not user:
            flash("Username does not exist.", "danger")
            return render_template('login.html', form=form)

        # Reset log in attempts when time is served
        if user.locked and user.lockedUntil <= datetime.now():
            user.failedLogin = 0
            user.locked = False
            db.session.commit()  # Commit the change to the database

        if user and bcrypt.check_password_hash(user.password, password):
            if (user.locked and user.lockedUntil <= datetime.now()) or not user.locked:
                session['username'] = form.username.data
                username = session.get('username')
                if user.fa_enabled:
                    return redirect(url_for('confirmation'))
                else:
                    login_user(user)
                    user.failedLogin = 0  # Reset failed login attempts for a successful login
                    user.locked = False  # Unlock the account
                    db.session.commit()  # Commit the change to the database
                    return redirect(url_for("dashboard"))

        else:
            user.failedLogin += 1
            db.session.commit()  # Commit the change to the database

            if user.failedLogin >= 3:
                user.locked = True
                user.lockedUntil = datetime.now() + timedelta(minutes=1)
                db.session.commit()  # Commit the change to the database
                flash("Account locked due to consecutive failed login attempts. Try again later.", "danger")

    return render_template('login.html', form=form)

# Route for the user dashboard with authentication check
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if not current_user.fa_enabled:
        # If 2FA is not enabled, display a button/link to enable it
        return render_template('dashboard.html', enable_2fa=True)
    # Render the dashboard page with an option to enable 2FA

    return render_template('dashboard.html', enable_2fa=False)
# Route to the user dashboard, requiring authentication

# Route for user logout with authentication check
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))
# Handle user logout and redirect to the login page

# Route for user confirmation (2FA) with session and form handling
@app.route('/confirmation', methods=['GET', 'POST'])
def confirmation():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    # If the user is already authenticated, redirect them to the dashboard

    if not session.get('username'):
        return redirect(url_for('login'))
    # If there is no username in the session, redirect to the login page

    username = session.get('username')
    if request.method == 'POST':
        otp_str = request.form.get("2fa_key")
        # Retrieve the 2FA token from the form

        if otp_str:
            try:
                otp = int(otp_str)
            except ValueError:
                flash("Invalid OTP format", "danger")
                # Check if the OTP is in the correct format

            user = User.query.filter_by(username=username).first()

            if user:
                user_secret = user.secret
                totp = pyotp.TOTP(user_secret)

                if totp.verify(otp):
                    session['message'] = "The TOTP 2FA token is valid"
                    session['message_type'] = "success"
                    login_user(user)
                    return redirect(url_for("dashboard"))
                else:
                    session['message'] = "The TOTP 2FA token is invalid"
                    session['message_type'] = "danger"
                    return redirect(url_for('confirmation'))
                # Verify the 2FA token and log in the user if valid

    return render_template("confirmation.html")
# Route for user confirmation page and 2FA verification

# Route for user registration with form validation
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # Create a registration form instance

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        secret = pyotp.random_base32()
        new_user = User(username=form.username.data, password=hashed_password, secret=secret)
        db.session.add(new_user)
        db.session.commit()
        # If the registration form is submitted and valid, create a new user in the database
        return redirect(url_for('login'))

    if form.username.data:
        flash("Username is already taken", "danger")
    return render_template('register.html', form=form)
# Route for user registration with form validation

# Route for enabling 2FA with form handling and PyOTP
@app.route("/register_2fa", methods=['GET', 'POST'])
@login_required
def enable():
    if current_user.fa_enabled:
        return redirect(url_for('dashboard'))
    # If 2FA is already enabled, redirect to the dashboard

    secret = current_user.secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name='AppName', issuer_name='IssuerName')
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_array = io.BytesIO()
    img.save(img_byte_array)
    img_byte_array.seek(0)
    img_data_base64 = base64.b64encode(img_byte_array.getvalue()).decode('utf-8')
    # Generate a QR code for 2FA setup

    if request.method == 'POST':
        otp_str = request.form.get("otp")
        # Retrieve the OTP entered by the user

        if otp_str is not None:
            try:
                otp = int(otp_str)
            except ValueError:
                flash("Invalid OTP format", "danger")
                # Check if the OTP is in the correct format

        if totp.verify(otp):
            current_user.fa_enabled = True
            db.session.commit()
            flash("The TOTP 2FA token is valid", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("You have supplied an invalid 2FA token!", "danger")
    # Verify the user's OTP and enable 2FA if valid

    return render_template("entertwostep.html", secret=secret, qr_code_path=img_data_base64)
# Route for enabling 2FA with form handling and PyOTP

# Main Execution
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)