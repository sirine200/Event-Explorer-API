# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json 
from werkzeug.security import check_password_hash


db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Updated to store hashed password
    events = db.relationship('Event', backref='organizer', lazy=True)
    bookmarks = db.relationship('Bookmark', backref='user', lazy=True)
    # Function to get all users in JSON format
    @staticmethod
    def get_all_users():
     users = User.query.all()
     users_info = [
        {"id": user.id, "username": user.username, "email": user.email}
        for user in users
     ]
     return json.dumps(users_info)
 
     # Add this method for password verification
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    location = db.Column(db.String(100))  # Added location field
    category = db.Column(db.String(50))  # Added category field
    image = db.Column(db.String(255))  # Assuming a file path or URL for simplicity
    price = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    participants = db.relationship('Participant', backref='event_relationship', lazy=True)
    # New fields for ticketing
    tickets_available = db.Column(db.Integer, default=0)
    ticket_price = db.Column(db.Float, default=10.0)


class Participant(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), primary_key=True)
    # Adding a relationship reference to the Event model
    event = db.relationship('Event', backref='participants_relationship', lazy=True)
    # New field for tracking the number of tickets purchased
    num_tickets_purchased = db.Column(db.Integer, default=0)

class Bookmark(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), primary_key=True)
    # Adding a relationship reference to the Event model
    event = db.relationship('Event', backref='bookmarks', lazy=True)

