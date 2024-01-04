import flask
from flask import Flask, render_template, request, redirect,url_for, session, flash, Response, send_file
from markupsafe import Markup
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re, hashlib
from requests.auth import HTTPBasicAuth
from datetime import datetime
import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')
from datetime import datetime
from dotenv import load_dotenv
import os
from functools import wraps
from werkzeug.security import generate_password_hash
import base64
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from flask_mail import Mail, Message
import jwt
import smtplib, ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import check_password_hash
from tensorflow.keras.models import load_model
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Image as ReportLabImage



app = Flask(__name__)
load_dotenv()

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = os.getenv('app.secret_key')

# access token
consumerKey = os.getenv('consumerKey') #Fill with your app Consumer Key
consumerSecret = os.getenv('consumerSecret') # Fill with your app Secret
base_url = os.getenv('base_url')

##Set up the configuration for flask_mail.
app.config['MAIL_SERVER']=os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
##update it with your gmail
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
##update it with your password
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
##app.config["EMAIL_SENDER"] = os.getenv('MAIL_SENDER')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')


# Enter your database connection details below
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')


# Intialize MySQL
mysql = MySQL(app)

#Create an instance of Mail.
mail = Mail(app)

model = load_model('model.h5')

with open('tokenizer.pkl', 'rb') as handle:
    tokenizer = pickle.load(handle)

maxlen=1000

@app.route('/', methods=['GET'])
def home():
  return render_template('index.html')

@ app.route('/home2')
def home2():
    # Check if user is loggedin
    if 'loggedin' in session:
        # User is loggedin show them the home page
        return render_template('index_2.html', username=session['username'],title="Home")
    # User is not loggedin redirect to login page
    return redirect(url_for('login')) 

@app.route('/project', methods=['GET'])
def project():
  username = None
  if 'username' in session:
    username = session['username']
  return render_template('project_main.html', username=username)



@app.route('/error', methods=['GET'])
def error():
  username = None
  if 'username' in session:
    username = session['username']
  return render_template('404.html', username=username)

@app.route('/contact', methods=['GET'])
def contact():
  username = None
  if 'username' in session:
    username = session['username']
  return render_template('contact.html', username=username)

@app.route('/about', methods=['GET'])
def about():
  username = None
  if 'username' in session:
    username = session['username']
  return render_template('about.html', username=username)

@app.route('/news', methods=['GET'])
def news():
  username = None
  if 'username' in session:
    username = session['username']
  return render_template('news.html', username=username)

@app.route('/single-news', methods=['GET'])
def singlenews():
  username = None
  if 'username' in session:
    username = session['username']
  return render_template('single-news.html', username=username)

@app.route('/run_model', methods=['GET', "POST"])
def run_model():
  if request.method == "POST":
    data=request.form['message']
    x=[data]
    x=tokenizer.texts_to_sequences(x)
    x=pad_sequences(x,maxlen=maxlen)
    y_pred=(model.predict(x))*100
    if 'username' in session:
        username = session['username']
    # Store the image, user's name, and the result in the database
    
    cur = mysql.connection.cursor()
    # Fetch the user's id
    prediction=str(y_pred)
    cur.execute("SELECT id FROM users WHERE username = %s", (session['username'],))
    user_id = cur.fetchone()[0]
    cur.execute("INSERT INTO userarticle(username, article, result, user_id) VALUES (%s, %s, %s, %s)", (session['username'], data, prediction,user_id))
    mysql.connection.commit()
    cur.close()
   
    return render_template('result.html', prediction=str(y_pred), username=username)
  return render_template('project_main.html')

@app.route('/feedback')
def feedback():
  return render_template('feedback.html')

@app.route('/insert',methods=['post'])
def insert():
  try:
    feedback = request.form['feedback']
    with sqlite3.connect("user_feedback.db") as conn:
        cur = conn.cursor()
        cur.execute("insert into feedback (user_feedback) values(?)", [feedback])
        conn.commit()
  except:
    conn = sqlite3.connect("user_feedback.db")
    conn.execute('create table feedback(feedback_id INTEGER PRIMARY KEY,user_feedback text)')
    feedback = request.form['feedback']
    with sqlite3.connect("user_feedback.db") as conn:
        cur = conn.cursor()
        cur.execute("insert into feedback (user_feedback) values(?)", [feedback])
        conn.commit()

  return render_template('feedback.html')

@app.route('/select')
def select_all_records():
    with sqlite3.connect("user_feedback.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("select * from feedback")
        rows = cur.fetchall()
    return render_template("content.html", rows_content=rows)



#################login and register#############################
@ app.route('/login')
def login():
    return render_template('authentication/index.html')

# http://localhost:5000/login/ - this will be the login page, we need to use both GET and POST requests
@app.route('/logini', methods=['GET', 'POST'])
def logini():
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']


        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], password):
            cursor.execute('SELECT * FROM users WHERE email = %s AND status = 1', (email,))
            verified_account = cursor.fetchone()
            if verified_account:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                mysql.connection.commit()

                return redirect(url_for('home2'))
            else:
                msg = 'Account not verified!'
                flash("Account not verified!", "danger")
        else:
            msg = 'Incorrect username/password!'
            flash("Incorrect username/password!", "danger")

    return render_template('authentication/index.html', msg=msg)
# http://localhost:5000/pythonlogin/register 
# This will be the registration page, we need to use both GET and POST requests
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'uname' in request.form and 'password' in request.form and 'email' in request.form:
        # Create variables for easy access
        username = request.form['uname']
        password = request.form['password']
        email_address = request.form['email']
        status = 0
                # Check if account exists using MySQL
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # cursor.execute('SELECT * FROM userss WHERE username = %s', (username))
        cursor.execute( "SELECT * FROM users WHERE email LIKE %s", [email_address] )
        account = cursor.fetchone()
        # If account exists show error and validation checks
        if account:
            flash("Account already exists!", "danger")
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email_address):
            flash("Invalid email address!", "danger")
        elif not re.match(r'[A-Za-z0-9]+', username):
            flash("Username must contain only characters and numbers!", "danger")
        elif not username or not password or not email_address:
            flash("Incorrect username/password!", "danger")
        else:
    
            # Hash the password
            password = generate_password_hash(request.form['password'])
            # Account doesnt exists and the form data is valid, now insert new account into accounts table
            cursor.execute('INSERT INTO users VALUES (NULL, %s, %s, %s, %s)', (username,email_address, password, status))
            mysql.connection.commit()
            token = jwt.encode(
                {
                    "email_address": email_address,
                    "password": password,
                }, os.getenv('app.secret_key')
            )

            # Ensure the token is a byte string
            if isinstance(token, str):
                token = token.encode()

            # Now you can decode the token
            decoded_data = jwt.decode(token, os.getenv('app.secret_key'), algorithms=["HS256"])
            #print(f"Type of email_address: {type(email_address)}")
            port = os.getenv('port')  # For starttls
            smtp_server = os.getenv('smtp_server')
            sender_email = os.getenv('sender_email')
            receiver_email = email_address
            password = os.getenv('password')
            try:
                # Convert the token to a string
                token_str = token.decode('utf-8')
                message = MIMEMultipart("alternative")
                message["Subject"] = "OTP"
                message["From"] = sender_email
                message["To"] = receiver_email

                # Create the plain-text and HTML version of your message
                text = """\
                Hi,
                Dear user, Your verification OTP code is {token}
                With regards,
                PandAid""".format(token=token_str)
                html = """\
                <html>
                <body>
                    <p>Hi,<br>
                    Dear user, </p> <h3>Your verification OTP code is </h3>
                    <br><br>
                      {token}
                    </p>
                    <br><br>
                    <p>With regards,</p>
                    <b>PandAid</b>
                </body>
                </html>
                """.format(token=token_str)

                # Turn these into plain/html MIMEText objects
                part1 = MIMEText(text, "plain")
                part2 = MIMEText(html, "html")

                # Add HTML/plain-text parts to MIMEMultipart message
                # The email client will try to render the last part first
                message.attach(part1)
                message.attach(part2)

                context = ssl.create_default_context()
                with smtplib.SMTP(smtp_server, port) as server:
                    server.ehlo()  # Can be omitted
                    server.starttls(context=context)
                    server.ehlo()  # Can be omitted
                    server.login(sender_email, password)
                    server.sendmail(sender_email, receiver_email, message.as_string())
                
            except Exception as e:
                print(f"Error sending email: {e}")
            return render_template("authentication/verify_email.html")

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Fill form'
        flash("Please fill out the form!", "danger")
    # Show registration form with message (if any)
    msg = 'error'
    return render_template('authentication/index.html', msg = msg)


# http://localhost:5000/pythinlogin/profile - this will be the profile page, only accessible for logged in users
@app.route('/profile')
def profile():
    # Check if the user is logged in
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        # Show the profile page with account info
        return render_template('authentication/profile.html', account=account, username=session['username'])
    # User is not logged in redirect to login page
    return redirect(url_for('login'))

@app.route('/edit_profile/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
def edit_profile(modifier_id, act):
	if act == "add":
		return render_template('authentication/edit_profile.html', data="", act="add")
	else:
		data = fetch_one(mysql, "users", "id", modifier_id)
	
		if data:
			return render_template('authentication/edit_profile.html', data=data, act=act, username=session['username'])
		else:
			return 'Error loading #%s' % modifier_id
          
@app.route('/saveprofile', methods=['GET', 'POST'])
def saveprofile():
	cat = ''
	if request.method == 'POST':
		post_data = request.form.to_dict()
		if 'password' in post_data:
			post_data['password'] = generate_password_hash(post_data['password']) 
		if post_data['act'] == 'add':
			cat = post_data['cat']
			insert_one(mysql, cat, post_data)
		elif post_data['act'] == 'edit':
			cat = post_data['cat']
			update_one(mysql, cat, post_data, post_data['modifier'], post_data['id'])
	else:
		if request.args['act'] == 'delete':
			cat = request.args['cat']
			delete_one(mysql, cat, request.args['modifier'], request.args['id'])
	return redirect("/home2")


# http://localhost:5000/python/logout - this will be the logout page
@app.route('/logout')
def logout():
    # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('username', None)
   # Redirect to login page
   return redirect(url_for('login'))

############OTP
@app.route("/verify-email", methods=['GET', 'POST'])
def verify_email():
    msg = ''
    try:
        if request.method == 'POST':
            token = request.form['token']
            data = jwt.decode(token, os.getenv('app.secret_key'),algorithms=["HS256"])
            email_address = data["email_address"]
            password = data["password"]
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("UPDATE users SET status = 1 WHERE email = %s", (email_address,))
            mysql.connection.commit()

            msg = 'Account verified'
            flash("Your account has successfully been registered!", "success")
            return render_template('authentication/index.html', msg=msg)
        elif request.method == 'GET':
            return render_template('authentication/verify_email.html', msg=msg)
    except jwt.DecodeError:
        flash("Invalid token!", "danger")
        return render_template('authentication/verify_email.html', msg='Invalid token')
    except Exception as e:
        flash(str(e), "danger")
        return render_template('authentication/verify_email.html', msg='An error occurred')


###################
####Recover########
###################
@app.route('/forgot_password')
def forgot_password():
     return render_template("authentication/recover.html")
@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        email_address = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # cursor.execute('SELECT * FROM users WHERE username = %s', (username))
        cursor.execute( "SELECT * FROM users WHERE email LIKE %s", [email_address] )
        account = cursor.fetchone()

        if account:
            serializer = URLSafeTimedSerializer(os.getenv('app.secret_key'))
            token = serializer.dumps(email_address, salt = os.getenv('salt'))

            port = os.getenv('port')  # For starttls
            smtp_server = os.getenv('smtp_server')
            sender_email = os.getenv('sender_email')
            receiver_email = email_address
            password = os.getenv('password')

            # Convert the token to a string
            #token_str = token.decode('utf-8')

            link = url_for('reset_with_token', token=token, _external=True)


            try:
                
                message = MIMEMultipart("alternative")
                message["Subject"] = "Password Reset Request"
                message["From"] = sender_email
                message["To"] = receiver_email

                # Create the plain-text and HTML version of your message
                text = """\
                Hi,
                Your link is {}
                With regards,
                PandAid""".format(link)
                html = """\
                <html>
                <body>
                    <p>Hi,<br>
                    Dear user, </p> <h3>Your link is </h3>
                    <br><br>
                      {}
                    </p>
                    <br><br>
                    <p>With regards,</p>
                    <b>PandAid</b>
                </body>
                </html>
                """.format(link)

                # Turn these into plain/html MIMEText objects
                part1 = MIMEText(text, "plain")
                part2 = MIMEText(html, "html")

                # Add HTML/plain-text parts to MIMEMultipart message
                # The email client will try to render the last part first
                message.attach(part1)
                message.attach(part2)

                context = ssl.create_default_context()
                with smtplib.SMTP(smtp_server, port) as server:
                    server.ehlo()  # Can be omitted
                    server.starttls(context=context)
                    server.ehlo()  # Can be omitted
                    server.login(sender_email, password)
                    server.sendmail(sender_email, receiver_email, message.as_string())
                flash('An email has been sent with instructions to reset your password.', 'success')
                
            except Exception as e:
                print(f"Error sending email: {e}")
                return render_template("authentication/recover.html")
        else:
            flash('No account found for that email address.', 'danger')

    return render_template('authentication/recover.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    try:
        serializer = URLSafeTimedSerializer(os.getenv('app.secret_key'))
        email_address = serializer.loads(token, salt=os.getenv('salt'), max_age=3600)
        return render_template('authentication/reset_with_token.html', token=token, _external=True)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('recover'))
    
@app.route('/rst', methods = ['GET', 'POST'])
def rst():
    if request.method == 'POST':
        token = request.form['token']
        serializer = URLSafeTimedSerializer(os.getenv('app.secret_key'))
        email_address = serializer.loads(token, salt=os.getenv('salt'), max_age=3600)
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('authentication/reset_with_token.html')
        # Hash the password
        password = generate_password_hash(request.form['password'])
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("UPDATE users SET password = %s WHERE email = %s", (password, email_address,))
        mysql.connection.commit()

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('authentication/reset_with_token.html')


###################
####CONTACT MODULE########
###################
@app.route('/questions', methods=['GET', 'POST'])
def questions():
     if request.method == 'POST' and 'name' in request.form and 'email' in request.form and 'subject' in request.form and 'message' in request.form and 'phone' in request.form:
            name = request.form['name']
            email_address = request.form['email']
            phone = request.form['phone']
            subject = request.form['subject']
            message = request.form['message']

            port = os.getenv('port')  # For starttls
            smtp_server = os.getenv('smtp_server')
            sender_email = os.getenv('sender_email')
            receiver_email = email_address
            password = os.getenv('password')
            try:
                message = MIMEMultipart("alternative")
                message["Subject"] = subject
                message["From"] = sender_email
                message["To"] = receiver_email

                # Create the plain-text and HTML version of your message
                text = """\
                Hi {name},
                Thank you for contacting us and we will attend to you right away
                With regards,
                PandAid""".format(name = name)
                html = """\
                <html>
                <body>
                    <p>Hi {name},<br>
                    Thank you for contacting us and we will attend to you right away
                    <br><br>
                    </p>
                    <br><br>
                    <p>With regards,</p>
                    <b>PandAid</b>
                </body>
                </html>
                """.format(name = name)

                # Turn these into plain/html MIMEText objects
                part1 = MIMEText(text, "plain")
                part2 = MIMEText(html, "html")

                # Add HTML/plain-text parts to MIMEMultipart message
                # The email client will try to render the last part first
                message.attach(part1)
                message.attach(part2)

                context = ssl.create_default_context()
                with smtplib.SMTP(smtp_server, port) as server:
                    server.ehlo()  # Can be omitted
                    server.starttls(context=context)
                    server.ehlo()  # Can be omitted
                    server.login(sender_email, password)
                    server.sendmail(sender_email, receiver_email, message.as_string())
                flash('Your message has been sent', 'success')
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Error sending email', 'danger')
            return redirect(url_for('contact'))
     return render_template('contact.html')


##ADMIN 
####################################
def login_required(f):
	@wraps(f)
	def wrapped(*args, **kwargs):
		if 'authorised' not in session:
			return render_template('admin/login.html')
		return f(*args, **kwargs)
	return wrapped


@app.context_processor
def inject_tables_and_counts():
	data = count_all(mysql)
	return dict(tables_and_counts=data)


@app.route('/admin')
@app.route('/admin')
@login_required
def index():
	return render_template('admin/index.html')


@app.route("/users")
@login_required
def users():
	data = fetch_all(mysql, "users")
	return render_template('admin/users.html', data=data, table_count=len(data))


@app.route('/edit_users/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_users(modifier_id, act):
	if act == "add":
		return render_template('admin/edit_users.html', data="", act="add")
	else:
		data = fetch_one(mysql, "users", "id", modifier_id)
	
		if data:
			return render_template('admin/edit_users.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id


@app.route("/admintable")
@login_required
def admintable():
	data = fetch_all(mysql, "admintable")
	return render_template('admin/admintable.html', data=data, table_count=len(data))


@app.route('/edit_admintable/<string:act>/<int:modifier_id>', methods=['GET', 'POST'])
@login_required
def edit_admintable(modifier_id, act):
	if act == "add":
		return render_template('admin/edit_admintable.html', data="", act="add")
	else:
		data = fetch_one(mysql, "admintable", "id", modifier_id)
	
		if data:
			return render_template('admin/edit_admintable.html', data=data, act=act)
		else:
			return 'Error loading #%s' % modifier_id

@app.route("/userarticle")
@login_required
def userarticle():
	data = fetch_all(mysql, "userarticle")
	return render_template('admin/userarticle.html', data=data, table_count=len(data))


@app.route('/save', methods=['GET', 'POST'])
@login_required
def save():
	cat = ''
	if request.method == 'POST':
		post_data = request.form.to_dict()
		if 'password' in post_data:
			post_data['password'] = generate_password_hash(post_data['password']) 
		if post_data['act'] == 'add':
			cat = post_data['cat']
			insert_one(mysql, cat, post_data)
		elif post_data['act'] == 'edit':
			cat = post_data['cat']
			update_one(mysql, cat, post_data, post_data['modifier'], post_data['id'])
	else:
		if request.args['act'] == 'delete':
			cat = request.args['cat']
			delete_one(mysql, cat, request.args['modifier'], request.args['id'])
	return redirect("./" + cat)


@app.route('/adminlogin')
def adminlogin():
	if 'authorised' in session:
		return redirect(url_for('admin'))
	else:
		error = request.args['error'] if 'error' in request.args else ''
		return render_template('admin/login.html', error=error)


@app.route('/login_handler', methods=['POST'])
def login_handler():
    email = request.form['email']
    password = request.form['password']
    #print(f"Email: {email}, Password: {password}")  # Debug print
    try:
        data = fetch_one(mysql, "admintable", "email", email)
        #print(f"Data fetched from database: {data}")  # Debug print
    except Exception as e:
        return render_template('admin/login.html', error=str(e))

    if data and len(data) > 0:
        password_check = check_password_hash(data['password'], password)
        #print(f"Password check result: {password_check}")  # Debug print
        if password_check:
            session['authorised'] = 'authorised',
            session['id'] = data['id']
            session['name'] = data['name']
            session['email'] = data['email']
            session['role'] = data['role']
            return redirect(url_for('index'))
        else:
            return redirect(url_for('adminlogin', error='Wrong Email address or Password.'))
    else:
        return redirect(url_for('adminlogin', error='No user'))


@app.route('/adminlogout')
@login_required
def adminlogout():
	session.clear()
	return redirect(url_for('adminlogin'))


def fetch_all(mysql, table_name):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT * FROM " + table_name)
	data = cursor.fetchall()
	if data is None:
		return "Problem!"
	else:
		return data


def fetch_one(mysql, table_name, column, value):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT * FROM " + table_name + " WHERE " + column + " = '" + str(value) + "'")
	data = cursor.fetchone()
	if data is None:
		return "Problem!"
	else:
		return data


def count_all(mysql):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    data = ()
    
    for table in tables:
        # Check if the table list is not empty
        if table:
            table_name = table['Tables_in_' + app.config['MYSQL_DB']]
            data += ((table_name, count_table(mysql, table_name)),)
    
    return data


def count_table(mysql, table_name):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT COUNT(*) as count FROM " + table_name)
    table_count = cursor.fetchone()
    return table_count['count']


def clean_data(data):
	del data["cat"]
	del data["act"]
	del data["id"]
	del data["modifier"]
	return data


def insert_one(mysql, table_name, data):
    data = clean_data(data)
    columns = ','.join(data.keys())
    values = ','.join([str("'" + e + "'") for e in data.values()])
    insert_command = "INSERT into " + table_name + " (%s) VALUES (%s) " % (columns, values)
    try:
        cursor = mysql.connection.cursor()
        cursor.execute(insert_command)
        mysql.connection.commit()
        return True
    except Exception as e:
        print("Problem inserting into db: " + str(e))
        return False


def update_one(mysql, table_name, data, modifier, item_id):
	data = clean_data(data)
	update_command = "UPDATE " + table_name + " SET {} WHERE " + modifier + " = " + item_id + " LIMIT 1"
	update_command = update_command.format(", ".join("{}= '{}'".format(k, v) for k, v in data.items()))
	try:
		cursor = mysql.connection.cursor()
		cursor.execute(update_command)
		mysql.connection.commit()
		return True
	except Exception as e:
		print("Problem updating into db: " + str(e))
		return False


def delete_one(mysql, table_name, modifier, item_id):
	try:
		cursor = mysql.connection.cursor()
		delete_command = "DELETE FROM " + table_name + " WHERE " + modifier + " = " + item_id + " LIMIT 1"
		cursor.execute(delete_command)
		mysql.connection.commit()
		return True
	except Exception as e:
		print("Problem deleting from db: " + str(e))
		return False
      




@app.route('/report', methods=['GET'])
@login_required
def report():
    # Connect to the database
    cur = mysql.connection.cursor()

    # Execute a SELECT query to get the data from userarticle table
    cur.execute("SELECT * FROM userarticle")
    images_data = cur.fetchall()

    # Get the column names from the cursor description
    column_names = [desc[0] for desc in cur.description]

    # Add the column names as the first row of the data
    images_data = [column_names] + list(images_data)

    cur.close()

    # Create a new PDF file
    pdf_file = os.path.join('static', 'report.pdf')
    doc = SimpleDocTemplate(pdf_file, pagesize=letter)

    # Add the heading and logo to the PDF
    styles = getSampleStyleSheet()
    title = Paragraph("PandAid", styles['Title'])
    logo_path = os.path.join('static', 'images', 'logo-no-background.png')
    logo = ReportLabImage(logo_path, width=100, height=50)  # Adjust the path and dimensions as needed

    # Add a new paragraph
    paragraph_text = "The importance of accurate news should never be underestimated. It is the foundation of a healthy democracy, and it is the responsibility of each and every one of us to seek out the truth."
    paragraph = Paragraph(paragraph_text, styles['BodyText'])

    # Create the tables
    images_table = Table(images_data)

    # Customize the appearance of the tables
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),

        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),

        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0,0), (-1,-1), 1, colors.black)
    ])
    images_table.setStyle(style)

    # Add the elements to the PDF
    elements = [title, logo, Spacer(1, 50), paragraph, Spacer(1, 20), images_table]
    doc.build(elements)

    return send_file(pdf_file, as_attachment=True, download_name='report.pdf')


if __name__ == "__main__":
	app.run(debug=True)