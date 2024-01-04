import flask
from flask import Flask, render_template, request, redirect,url_for, session, flash, Response, send_file
from markupsafe import Markup
from flask_mysqldb import MySQL
import pickle
import numpy as np
import warnings
warnings.filterwarnings('ignore')
from datetime import datetime
from dotenv import load_dotenv
import os
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

@app.route('/home1', methods=['GET'])
def home1():
  return render_template('index_2.html')

@app.route('/error', methods=['GET'])
def error():
  return render_template('404.html')

@app.route('/contact', methods=['GET'])
def contact():
  return render_template('contact.html')

@app.route('/about', methods=['GET'])
def about():
  return render_template('about.html')

@app.route('/news', methods=['GET'])
def news():
  return render_template('news.html')

@app.route('/', methods=['GET', "POST"])
def run_model():
  if request.method == "POST":
    data=request.form['a']
    x=[data]
    x=tokenizer.texts_to_sequences(x)
    x=pad_sequences(x,maxlen=maxlen)
    y_pred=(model.predict(x))*100
   
    return render_template('result.html', prediction=str(y_pred))
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

    return render_template('login/signup-login.html', msg=msg)
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
     return render_template("login/recover.html")
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
        return render_template('login/reset_with_token.html', token=token, _external=True)
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


if __name__ == "__main__":
	app.run(debug=True)