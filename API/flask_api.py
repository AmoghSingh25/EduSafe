from flask import Flask, jsonify, request
import logging
import psycopg2
import os
from dotenv import load_dotenv
import uuid
from datetime import date
import requests
import hashlib
from psycopg2.extensions import AsIs, quote_ident
from twilio.rest import Client
from flask_cors import CORS, cross_origin
import cohere


load_dotenv()

DB_URL = os.getenv('DB_URL')

app = Flask(__name__)
CORS(app)
cors = CORS(app, resource={
    r"/*": {
        "origins": "*"
    }
})
logging.getLogger('flask_cors').level = logging.DEBUG
conn = psycopg2.connect(DB_URL)
chat_api_key = os.getenv('CHAT_API_KEY')
cur = conn.cursor()
student_role_id = os.getenv('STUDENT_ROLE_ID')
COHERE_KEY = os.getenv('COHERE_KEY')
account_sid = os.environ['TWILIO_ACCOUNT_SID']
auth_token = os.environ['TWILIO_AUTH_TOKEN']
client = Client(account_sid, auth_token)

SERVICE_SID = os.getenv('SERVICE_SID')


@app.route('/', methods=['POST'])
def home():
    cur.execute('DELETE FROM USERS')
    conn.commit()
    return jsonify({"message": "Complete"})


@app.route('/creation_db', methods=['POST'])
def create_table():
    cur.execute("CREATE TABLE IF NOT EXISTS USERS (id UUID PRIMARY KEY, name STRING NOT NULL, password CHAR(128) NOT NULL, email STRING NOT NULL, phone CHAR(15) NOT NULL)")
    conn.commit()
    return jsonify({'message': 'Table created'})


@app.route('/get_db', methods=['POST'])
def get_conotents():
    # name = str(request.get_json()['db'])
    cur.execute('SELECT * FROM CLASSES')
    print(cur.fetchall())
    return jsonify({'message': 'Table created'})


@app.route('/create_class', methods=['POST'])
def create_class():
    data = request.get_json()
    name = data['class_name']
    new_uid = str(uuid.uuid4().hex)
    cur.execute("INSERT INTO classes (id, name) VALUES (%s, %s)",
                (new_uid, name))
    cur.execute(
        "CREATE TABLE IF NOT EXISTS {} (memberID UUID PRIMARY KEY, memberName STRING NOT NULL)".format("_"+new_uid))
    conn.commit()
    url = "https://210878e4f4164401.api-us.cometchat.io/v3/groups"

    payload = {
        "metadata": {},
        "members": {},
        "guid": new_uid,
        "name": name,
        "type": "private"
    }
    headers = {
        "apiKey": chat_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers, timeout=10)
    response_text = response.text
    response.close()
    print(response_text)
    return jsonify({'message': response_text})


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()
    message = data['message']
    group_id = data['class_id']
    user_id = data['user_id']
    print(message)
    url = "https://210878e4f4164401.api-us.cometchat.io/v3/messages"

    payload = {
        "guid": group_id,
        "type": "text",
        "receiverType": "group",
        "receiver": group_id,
        "data": {
            "text": message,
        }
    }
    headers = {
        "apiKey": chat_api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "onBehalfOf": user_id,
    }

    response = requests.post(url, json=payload, headers=headers)

    print(response.text)
    return jsonify({'message': response.text})


@app.route('/profanity_check', methods=['POST'])
def profanity_check():
    data = request.get_json()
    message = data['message']
    co = cohere.Client(COHERE_KEY)
    classifications = co.classify(
    model='70792cf3-a4f6-4de7-a6b8-9b4cdebce7b9-ft',
    inputs=[message])
    resp = classifications.classifications[0].prediction
    return jsonify({'message': resp})


@app.route('/create_user', methods=['POST'])
def create_student():
    try:
        data = request.get_json()
        student_name = data['name']
        student_uid = str(uuid.uuid4())
        student_email = data['email']
        student_phone = data['phone']
        student_password = data['password']
        hashed_password = hashlib.sha256(str.encode(student_password))
        hashed_password = hashed_password.hexdigest()
        student = data['student_status']
        cur.execute("SELECT * FROM USERS WHERE email = %s", (student_email,))
        if cur.fetchone() is not None:
            return jsonify({'message': 'User already exists'})
        print(student_role_id)
        cur.execute("INSERT INTO users (id, name, password, email, phone) VALUES (%s, %s, %s, %s, %s)",
                    (student_uid, student_name, hashed_password, student_email, student_phone))
        conn.commit()
        verification = client.verify \
            .services(SERVICE_SID) \
            .verifications \
            .create(to=student_phone, channel='sms')

        url = "https://210878e4f4164401.api-us.cometchat.io/v3/users"

        payload = {
            "metadata": {"@private": {
                "email": student_email,
            }},
            "uid": student_uid,
            "name": student_name
        }
        if(student == True):
            payload['role'] = student_role_id
        headers = {
            "apiKey": chat_api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        response = requests.post(url, json=payload, headers=headers)

        print(response.text)
        resp = response.json()
        resp['status'] = 'success'
        print(resp)
        return resp
    except Exception as e:
        print(e)
        return jsonify({'message': str(e), 'status': 'fail'})


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp = data['otp']
    phone = "+"+data['phone'].strip()
    print(phone, otp)
    verification = client.verify \
        .services(SERVICE_SID) \
        .verification_checks \
        .create(to=phone, code=otp)
    print(verification.status)
    return jsonify({'message': verification.status})


@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.get_json()
    student_email = data['email']
    student_password = data['password']
    hashed_password = hashlib.sha256(str.encode(student_password))
    hashed_password = hashed_password.hexdigest()
    cur.execute("SELECT * FROM users WHERE email = %s AND password = %s",
                (student_email, hashed_password))
    user_data = cur.fetchone()
    if user_data is None:
        return jsonify({'message': 'Incorrect email or password', 'status': 'fail'})
    else:
        return jsonify({'message': 'Logged in', 'user_id': user_data[0], 'status': 'success'})


@app.route("/assign_class", methods=['POST'])
def assign_class():

    # ASsign to cometchat to be done using React
    data = request.get_json()
    class_id = data['class_id']
    student_id = data['student_id']
    cur.execute("INSERT INTO {} (memberID, memberName) VALUES (%s, %s)".format(
        "_"+class_id), (student_id, student_id))
    conn.commit()
    return jsonify({'message': 'Class assigned'})


@app.route('/get_all_users', methods=['POST'])
def get_users_table():
    cur.execute("SELECT * FROM USERS")
    classes = cur.fetchall()
    return jsonify({'message': classes})


@app.route('/get_users', methods=['POST'])
def get_users():
    try:
        data = request.get_json()
        class_id = data['class_id']
        class_id = uuid.UUID(class_id).hex
        cur.execute("SELECT * FROM {}".format("_"+class_id))
        members = cur.fetchall()
        print(members)
        return jsonify({'message': members})
    except Exception as e:
        cur.execute('ROLLBACK')
        conn.commit()
        return jsonify({'message': str(e)})

# Get all classes


@app.route('/get_classes', methods=['POST'])
def get_classes():
    cur.execute("SELECT * FROM CLASSES")
    classes = cur.fetchall()
    return jsonify({'message': classes})


if __name__ == '__main__':

    app.run(debug=True)
