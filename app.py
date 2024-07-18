from flask import Flask, render_template, jsonify, request, redirect, url_for, session
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import boto3
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure key in production
socketio = SocketIO(app)

# Set up logging
logging.basicConfig(filename='sensor_script.log', level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize DynamoDB resource
dynamodb = boto3.resource('dynamodb', region_name='us-east-2')
user_table_name = 'users'
patient_table_name = 'patients'

def create_user_table():
    try:
        existing_tables = list(dynamodb.tables.all())
        if user_table_name not in [table.name for table in existing_tables]:
            table = dynamodb.create_table(
                TableName=user_table_name,
                KeySchema=[
                    {
                        'AttributeName': 'email',
                        'KeyType': 'HASH'  # Partition key
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'email',
                        'AttributeType': 'S'
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            table.wait_until_exists()
            logger.info(f"Table {user_table_name} created successfully")
        else:
            logger.info(f"Table {user_table_name} already exists")
    except Exception as e:
        logger.error(f"Error creating table: {e}")

def create_patient_table():
    try:
        existing_tables = list(dynamodb.tables.all())
        if patient_table_name not in [table.name for table in existing_tables]:
            table = dynamodb.create_table(
                TableName=patient_table_name,
                KeySchema=[
                    {
                        'AttributeName': 'id',
                        'KeyType': 'HASH'  # Partition key
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'id',
                        'AttributeType': 'S'
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            table.wait_until_exists()
            logger.info(f"Table {patient_table_name} created successfully")
        else:
            logger.info(f"Table {patient_table_name} already exists")
    except Exception as e:
        logger.error(f"Error creating table: {e}")

create_user_table()
create_patient_table()

user_table = dynamodb.Table(user_table_name)
patient_table = dynamodb.Table(patient_table_name)

# Fetch all patient details from DynamoDB
def fetch_patient_details():
    try:
        response = patient_table.scan()
        return response['Items']
    except Exception as e:
        logger.error(f"Error fetching patient details: {e}")
        return []

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/doctor')
def doctor():
    try:
        logged_in_doctor_email = session.get('user_email', 'default@doctor.com')
        
        # Debugging statement
        print(f"Logged in doctor email: {logged_in_doctor_email}")

        response = user_table.get_item(
            Key={'email': logged_in_doctor_email}
        )
        if 'Item' in response:
            doctor_name = response['Item']['name']
        else:
            doctor_name = "Doctor's Name"
        
        # Debugging statement
        print(f"Fetched doctor name: {doctor_name}")

        patients = fetch_patient_details()

        # Debugging statement
        print(f"Patients: {patients}")

        user_role = session.get('user_role', 'guest')

        # Debugging statement
        print(f"User role: {user_role}")

        return render_template('doctor.html', patients=patients, doctor_name=doctor_name, user_role=user_role)
    except Exception as e:
        logger.error(f"Error rendering doctor.html: {e}")
        return "Internal Server Error", 500


@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        email = data['email']
        name = data['name']
        password = generate_password_hash(data['password'])
        
        response = user_table.put_item(
            Item={
                'email': email,
                'name': name,
                'password': password,
                'role': 'user'  # Default role
            }
        )
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error signing up: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/main')
def main():
    return render_template('main.html')

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data['email']
        password = data['password']
        
        response = user_table.get_item(
            Key={'email': email}
        )
        
        print("Response from DynamoDB:", response)  # Add this line for logging
        
        if 'Item' in response:
            user = response['Item']
            if check_password_hash(user['password'], password):
                session['user_email'] = email
                role = user.get('role')
                print("Role fetched:", role)  # Add this line for logging
                session['user_role'] = role
                return jsonify({'status': 'success', 'role': role})  # Return role in the response
            else:
                return jsonify({'status': 'error', 'message': 'Incorrect password'}), 401
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Error logging in: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500



@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('user_role', None)
    return redirect(url_for('main'))

@app.route('/add_patient', methods=['POST'])
def add_patient():
    try:
        data = request.json
        logger.debug(f"Received data to add patient: {data}")
        patient_table.put_item(Item=data)
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error adding patient: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/update_patient/<string:patient_id>', methods=['PUT'])
def update_patient(patient_id):
    try:
        data = request.json
        logger.debug(f"Received data to update patient {patient_id}: {data}")

        update_expression = "set #n = :n, #a = :a, #g = :g, #d = :d, #s = :s"
        expression_attribute_names = {
            '#n': 'name',
            '#a': 'age',
            '#g': 'gender',
            '#d': 'diagnosis',
            '#s': 'symptoms'
        }
        expression_attribute_values = {
            ':n': data['name'],
            ':a': data['age'],
            ':g': data['gender'],
            ':d': data['diagnosis'],
            ':s': data['symptoms']
        }
        
        response = patient_table.update_item(
            Key={'id': patient_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values
        )
        logger.info(f"Updated patient {patient_id} with data: {data}")
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error updating patient {patient_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/delete_patient/<string:patient_id>', methods=['DELETE'])
def delete_patient(patient_id):
    try:
        logger.debug(f"Received request to delete patient {patient_id}")
        patient_table.delete_item(Key={'id': patient_id})
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error deleting patient {patient_id}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/view_status/<string:patient_id>', methods=['GET'])
def view_status(patient_id):
    # Implement logic to fetch and display current status
    # Redirecting to index.html for demonstration purpose
    return redirect(url_for('index'))

@app.route('/index')
def index():
    # Dummy route for index.html, replace with actual logic
    return render_template('index.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/admin/doctors', methods=['GET'])
def get_doctors():
    try:
        response = user_table.scan()
        doctors = response['Items']
        return jsonify({'doctors': doctors})
    except Exception as e:
        logger.error(f"Error fetching doctors: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/add_doctor', methods=['POST'])
def add_doctor():
    try:
        data = request.json
        email = data['email']
        name = data['name']
        password = generate_password_hash(data['password'])
        role = data['role']

        # Ensure role is either 'user' or 'admin'
        if role not in ['user', 'admin']:
            return jsonify({'status': 'error', 'message': 'Invalid role. Role must be either "user" or "admin"'}), 400

        response = user_table.put_item(
            Item={
                'email': email,
                'name': name,
                'password': password,
                'role': role
            }
        )
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error adding doctor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/admin/delete_doctor/<string:email>', methods=['DELETE'])
def delete_doctor(email):
    try:
        user_table.delete_item(Key={'email': email})
        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Error deleting doctor: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/change_password', methods=['POST'])
def change_password():
    try:
        data = request.json
        email = session.get('user_email')
        current_password = data['current_password']
        new_password = data['new_password']
        
        if not email:
            return jsonify({'status': 'error', 'message': 'User not logged in'}), 401
        
        response = user_table.get_item(
            Key={'email': email}
        )
        
        if 'Item' in response:
            user = response['Item']
            if check_password_hash(user['password'], current_password):
                new_password_hash = generate_password_hash(new_password)
                user_table.update_item(
                    Key={'email': email},
                    UpdateExpression="set #p = :p",
                    ExpressionAttributeNames={'#p': 'password'},
                    ExpressionAttributeValues={':p': new_password_hash}
                )
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'error', 'message': 'Incorrect current password'}), 401
        else:
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
    except Exception as e:
        logger.error(f"Error changing password: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def start_flask():
    socketio.run(app, host='0.0.0.0', port=5001)
    
@app.route('/get_user_role', methods=['GET'])
def get_user_role():
    if 'user' in session:
        user_role = session['user'].get('role', 'guest')
        return jsonify({'role': user_role})
    return jsonify({'error': 'User not logged in'}), 401    

@app.route('/home')
def go_to_home():
    return redirect(url_for('home'))

# Start the Flask server in a separate thread
flask_thread = threading.Thread(target=start_flask)
flask_thread.start()
