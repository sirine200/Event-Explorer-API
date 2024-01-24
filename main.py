# main.py
from app import create_app,db
import logging
from app.models import User, Event, Participant, Bookmark
from flask import Flask

# Initialize the Flask app
app = create_app()


if __name__ == '__main__':
    with app.app_context():
        # Create database tables if they do not exist
        
        db.create_all()

        logging.info("Database tables created successfully.")

    app.run(debug=True, port=5000,ssl_context=('cert.pem', 'key.pem'))



