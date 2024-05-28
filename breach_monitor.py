import asyncio
import requests
import pymysql
from elasticsearch import Elasticsearch
from smtplib import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
import logging
import os
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_fixed

# Load environment variables from a .env file
load_dotenv()

# Set up logging
logging.basicConfig(filename='breach_monitor.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Configuration loaded from environment variables
mysql_config = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', 'password'),
    'db': os.getenv('MYSQL_DB', 'breaches')
}
es_host = os.getenv('ES_HOST', 'localhost:9200')
smtp_config = {
    'host': os.getenv('SMTP_HOST', 'smtp.example.com'),
    'port': int(os.getenv('SMTP_PORT', 587)),
    'user': os.getenv('SMTP_USER', 'user@example.com'),
    'password': os.getenv('SMTP_PASSWORD', 'password')
}
netbox_api_url = os.getenv('NETBOX_API_URL', 'https://netbox.example.com/api/')
netbox_token = f"Token {os.getenv('NETBOX_API_KEY')}"

# Connect to MySQL
db = pymysql.connect(**mysql_config)
cursor = db.cursor()

# Initialize and check MySQL tables
def init_mysql():
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS breaches (
            id INT AUTO_INCREMENT PRIMARY KEY,
            query VARCHAR(255),
            data TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.commit()

# Connect to Elasticsearch
es = Elasticsearch([{'host': es_host, 'port': 9200}])

# Initialize Elasticsearch indices
def init_elasticsearch():
    if not es.indices.exists(index='breaches'):
        index_settings = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "query": {"type": "text"},
                    "data": {"type": "text"},
                    "date": {"type": "date", "format": "epoch_millis"}
                }
            }
        }
        es.indices.create(index='breaches', body=index_settings)

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
async def check_breaches(query):
    try:
        url = f"https://haveibeenpwned.com/api/v3/{query}"
        headers = {'hibp-api-key': os.getenv('HIBP_API_KEY')}
        response = await requests.get(url, headers=headers)
        data = response.json()
        if data:
            cursor.execute("INSERT INTO breaches (query, data) VALUES (%s, %s)", (query, str(data)))
            db.commit()
            es.index(index='breaches', doc_type='_doc', body={'query': query, 'data': data, 'date': datetime.datetime.now()})
            return True
    except Exception as e:
        logging.error(f"Failed to check or store breach data for {query}: {str(e)}")
    return False

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
async def update_netbox(ip):
    try:
        netbox_headers = {'Authorization': netbox_token, 'Content-Type': 'application/json'}
        response = await requests.get(netbox_api_url + 'ip-addresses/', headers=netbox_headers, params={'address': ip})
        if response.status_code == 200:
            ip_data = response.json()
            if ip_data['results']:
                comment = 'Found in data breach'
                update_response = await requests.patch(netbox_api_url + 'ip-addresses/' + str(ip_data['results'][0]['id']), headers=netbox_headers, json={'description': comment})
                return update_response.status_code == 200
    except Exception as e:
        logging.error(f"Failed to update NetBox for IP {ip}: {str(e)}")
    return False

async def daily_check():
    init_mysql()
    init_elasticsearch()

    # Example dynamic queries could be loaded from a file or database
    queries = ['test@example.com', '192.168.1.1']
    for query in queries:
        if await check_breaches(query):
            if query.count('.') == 3:  # Simple check to assume it's an IP
                await update_netbox(query)
