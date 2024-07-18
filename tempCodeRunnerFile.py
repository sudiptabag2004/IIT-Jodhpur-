dynamodb = boto3.resource('dynamodb', region_name='us-east-2')
user_table_name = 'users'
patient_table_name = 'patients'