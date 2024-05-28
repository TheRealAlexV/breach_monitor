# Breach Monitor

https://github.com/TheRealAlexV/breach_monitor

## Overview
Breach Monitor is a Python script designed to check if an email address, IP, domain, hostname, or name has been found in any data breaches or compromises. It uses multiple public APIs and stores every finding in a MySQL database as well as in Elasticsearch. A daily report of findings is generated and sent via email.

## Configuration
Configure the script using the `.env` file where you can set up your database credentials, Elasticsearch host, SMTP settings for email alerts, NetBox API URL and key, and Have I Been Pwned API key.

## Requirements
- Python 3.9+
- Docker
- Docker Compose
- Access to SMTP server
- Have I Been Pwned API key
- NetBox installation

## Running the Script
To run the script:
1. Ensure Docker and Docker Compose are installed.
2. Set up your `.env` file with the appropriate configurations.
3. Build the Docker image and run it using Docker Compose:
   ```bash
   docker-compose up --build
