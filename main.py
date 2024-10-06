from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import MySQLdb.cursors
import re
import mysql.connector
import bcrypt
import logging
from flask_mail import Mail, Message
import secrets


app = Flask(__name__)
mail = Mail(app)

app.config['DEBUG'] = True
app.debug = True


# Configure the logging module
logging.basicConfig(filename='app.log', level=logging.DEBUG)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = ''
app.config['MAIL_PORT'] = 
app.config['MAIL_USE_TLS'] = 
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
mail = Mail(app)

# Connect to the database
mydb = mysql.connector.connect(
    host="localhost",
    user="",
    password="", 
    database="pythonlogin"
)
# Change this to your secret key (it can be anything, it's for extra protection)
app.secret_key = ''

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = ''
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'pythonlogin'
app = Flask(__name__, static_folder='static')


# Intialize MySQL
mysql = MySQL(app)


# Create a limiter object
limiter = Limiter(lambda: request.form.get('username', ''), app=app, default_limits=["10/minute"])



# http://localhost:5000/pythonlogin/ - the following will be our login page, which will use both GET and POST requests
@app.route('/efoodroject', methods=['GET', 'POST'])
@limiter.limit('2 per minute')

def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        
        # Log the username and password
        logging.debug(f"Received login request for username: {username}")

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))

        # Fetch one record and return the result
        account = cursor.fetchone()
 

        if account and bcrypt.checkpw(password.encode(), account['password'].encode()):
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']

            # Log the successful login
            logging.info(f"User logged in successfully: {username}")

            # Redirect to home page
            return redirect(url_for('home'))

        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'

            # Log the failed login attempt
            logging.warning(f"Failed login attempt for username: {username}")

    return render_template('index.html', msg=msg)

# http://localhost:5000/pythonlogin/logout - this will be the logout page
@app.route('/efoodroject/logout')
def logout():
    # Log the logout event
    logging.info(f"User logged out: {session['username']}")

    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)

    # Redirect to login page
    return redirect(url_for('login'))

# http://localhost:5000/pythonlogin/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/efoodroject/register', methods=['GET', 'POST'])
def register():
    # Output message if something goes wrong...
    msg = ''

    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Log the registration request
        logging.debug(f"Received registration request for username: {username}")

        # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        
        if account:
            msg = 'Account already exists!'

            # Log the account existing error
            logging.warning(f"Account already exists for username: {username}")

        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'

            # Log the invalid email address
            logging.warning(f"Invalid email address for username: {username}")

        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers!'

            # Log the invalid username
            logging.warning(f"Invalid username for registration: {username}")

        elif not username or not password or not email:
            msg = 'Please fill out the form!'

            # Log the missing form data
            logging.warning(f"Missing form data for registration: {username}")

        else:

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Generate activation token
            activation_token = secrets.token_hex(16)

            # Account doesn't exist, and the form data is valid, so insert the new account into the accounts table
            cursor.execute('INSERT INTO accounts (username, password, email, activation_token, is_active) VALUES (%s, %s, %s, %s, %s)', (username, hashed_password, email, activation_token, 0))
            mysql.connection.commit()
            msg = 'You have successfully registered! Please check your email to activate your account.'

            # Log the successful registration
            logging.info(f"User registered successfully: {username}")

            # Send the activation email
            send_activation_email(email, activation_token)
            
    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'

        # Log the empty form data
        logging.warning("Empty form data received for registration")

    # Show registration form with message (if any)
    return render_template('register.html', msg=msg)

# http://localhost:5000/pythinlogin/home - this will be the home page, only accessible for logged in users
@app.route('/efoodroject/home')
def home():
    # Check if the user is logged in
    if 'loggedin' in session:

        # Log the home page access event
        logging.info("User accessed home page")

        # User is loggedin show them the home page
        return render_template('home.html', username=session['username'])

    # User is not loggedin redirect to login page
    logging.info("User redirected to login page")
    return redirect(url_for('login'))

# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for logged in users
@app.route('/efoodroject/profile')
def profile():
    # Check if the user is logged in
    if 'loggedin' in session:

        # Log the profile page access event
        logging.info("User accessed profile page")

        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        # Show the profile page with account info
        return render_template('profile.html', account=account)

    # User is not logged in redirect to login page
    logging.info("User redirected to login page")
    return redirect(url_for('login'))

def send_activation_email(email, activation_token):
    # Prepare email message
    subject = "Account Activation"
    sender = app.config['MAIL_USERNAME']
    recipient = email
    activation_link = f"http://http://localhost:5000/pythonlogin/activate/{activation_token}"  # Replace with your activation route URL
    message_body = f"Dear user,\n\nPlease click on the following link to activate your account:\n{activation_link}"

 # Create and send email message
    with app.app_context():
        msg = Message(subject=subject, sender=sender, recipients=[recipient])
        msg.body = message_body
        mail.send(msg)
        
@app.route('/efoodroject/activate/<activation_token>')
def activate(activation_token):
    # Retrieve the user from the database based on the activation token
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE activation_token = %s', (activation_token,))
    account = cursor.fetchone()
    if account:
        # Activate the user's account by updating the database
        cursor.execute('UPDATE accounts SET is_active = 1 WHERE activation_token = %s', (activation_token,))
        mysql.connection.commit()
        # Display a success message or redirect to a login page
        return "Account activated successfully!"
    else:
        # Display an error message or redirect to an error page
        return "Invalid activation token."
    
if __name__ == '__main__':
    app.run()







