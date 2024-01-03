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

model = pickle.load(open('model.pkl', 'rb'))

@app.route('/', methods=['GET'])
def home():
  return render_template('project_main.html')

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



app.run()