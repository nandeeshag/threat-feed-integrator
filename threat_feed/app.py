import re
from flask import Flask, render_template, request
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from io import StringIO
import pandas as pd

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'threat_feeds'

mysql = MySQL(app)
bcrypt = Bcrypt(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Query the database to retrieve the hashed password for the given email
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and bcrypt.check_password_hash(user[0], password):
            # Login successful, password matches the stored hashed password
            return """<script>alert("Login Successful!!!"); window.location.href = '/home'; </script>"""
        else:
            # Login failed, show an alert
            return """<script>alert("Login failed. Please check your username and password."); 
                        window.location.href = '/login'; </script>"""

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Check if the email already exists in the database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            # Email already exists, show an error message
            cursor.close()
            return """<script>alert("Email is already registered. Please use a different email."); 
                        window.location.href = '/register'; </script>"""

        # Hash the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert user data (including the hashed password) into the 'users' table
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                       (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        return """<script>alert("Registration Successful! Now you can Login."); 
                    window.location.href = '/login'; </script>"""

    return render_template('register.html')


@app.route('/home')
def home():
    return render_template('home.html')


def fetch_and_save_data():
    url = 'https://phishstats.info:2096/api/phishing?_sort=-date'
    response = requests.get(url)
    data = []

    if response.status_code == 200:
        api_data = response.json()
        if api_data and isinstance(api_data, list):
            data = api_data

            cursor = mysql.connection.cursor()
            for item in data:
                date = item['date']
                url = item['url']
                ip = item['ip']
                hash = item['hash']

                # Check if data with the same IP and hash value already exists in the database
                cursor.execute("SELECT * FROM phishing_data WHERE ip = %s AND hash = %s", (ip, hash))
                existing_data = cursor.fetchone()

                if not existing_data:
                    # Data doesn't exist, so insert it into the database
                    cursor.execute("INSERT INTO phishing_data (url, ip, hash) VALUES (%s, %s, %s)",
                                   (date, url, ip, hash))
                    mysql.connection.commit()

            cursor.close()


# Create and configure the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(fetch_and_save_data, 'interval', hours=1)  # Send request every hour
scheduler.start()


@app.route('/phishstats')
def phishstats_data():
    url = 'https://phishstats.info:2096/api/phishing?_sort=-date'
    response = requests.get(url)
    data = []

    if response.status_code == 200:
        api_data = response.json()
        if api_data and isinstance(api_data, list):
            data = api_data

            cursor = mysql.connection.cursor()
            for item in data:
                date = item['date']
                url = item['url']
                ip = item['ip']
                hash = item['hash']

                # Check if data with the same IP and hash value already exists in the database
                cursor.execute("SELECT * FROM phishing_data WHERE ip = %s AND hash = %s", (ip, hash))
                existing_data = cursor.fetchone()

                if not existing_data:
                    # Data doesn't exist, so insert it into the database
                    cursor.execute("INSERT INTO phishing_data (url, ip, hash) VALUES (%s, %s, %s)",
                                   (url, ip, hash))
                    mysql.connection.commit()

            cursor.close()
    return render_template('phishstats.html', data=data)


def url_exists_in_database(url):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM openphish_urls WHERE url = %s", (url,))
    existing_url = cursor.fetchone()
    cursor.close()
    return existing_url is not None


@app.route('/openphish')
def openphish_data():
    url = 'https://openphish.com/feed.txt'
    response = requests.get(url)
    data = []

    if response.status_code == 200:
        text_data = response.text

        # Extract URLs from the text file using regular expressions
        urls = re.findall(r'https?://[^\s/$.?#].[^\s]*', text_data)

        for url in urls:
            if not url_exists_in_database(url):
                cursor = mysql.connection.cursor()
                cursor.execute("INSERT INTO openphish_urls (url) VALUES (%s)", (url,))
                mysql.connection.commit()
                cursor.close()

            data.append({'url': url})

    return render_template('openphish.html', data=data)


@app.route('/phishtank')
def display_data():
    url = 'https://data.phishtank.com/data/online-valid.csv'
    response = requests.get(url)
    data = []

    if response.status_code == 200:
        # Read the CSV data into a Pandas DataFrame
        csv_data = response.text
        df = pd.read_csv(StringIO(csv_data))

        # Extract URL and Submission Date columns
        url_column = df['url']
        submission_date_column = df['submission_time']

        # Create a list of dictionaries with URL and Submission Date, limiting to the top 200 entries
        data = [{'url': url, 'submission_date': submission_date} for url, submission_date in
                zip(url_column[:200], submission_date_column[:200])]

        # Insert data into the database
        cursor = mysql.connection.cursor()
        for item in data:
            url = item['url']
            submission_date = item['submission_date']

            # Check if data with the same URL already exists in the database
            cursor.execute("SELECT * FROM phishtank WHERE url = %s", (url,))
            existing_data = cursor.fetchone()

            if not existing_data:
                # Data doesn't exist, so insert it into the database
                cursor.execute("INSERT INTO phishtank (url, submission_date) VALUES (%s, %s)", (url, submission_date))
                mysql.connection.commit()

        cursor.close()
        data = [{'url': url, 'submission_date': submission_date} for url, submission_date in
                zip(url_column[:200], submission_date_column[:200])]
    return render_template('phishtank.html', data=data)


if __name__ == "__main__":
    app.run(debug=True)
