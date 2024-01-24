import os 
from flask import Blueprint, session, request, abort, jsonify, flash, redirect, url_for
from flask_login import current_user, login_required
from . import db
from .models import Event, User, Participant, Bookmark
from .forms import EventForm, RegistrationForm
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from flask_wtf.csrf import generate_csrf
from . import csrf
from flask import redirect, request, abort
from google.auth.transport import requests
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import create_access_token
from flask import jsonify, g
import google.auth.transport.requests
from flask_jwt_extended import jwt_required, get_jwt_identity


main_blueprint = Blueprint('main', __name__)

# Define flow and client_secrets here
client_secrets_file = 'client_secrets.json'
with open(client_secrets_file) as f:
    client_secrets = json.load(f)  # Load client_secrets

flow = InstalledAppFlow.from_client_secrets_file(
    r'C:\Users\Thinkpad\3D Objects\EventExplorer\client_secrets.json',
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

@main_blueprint.route('/')
def home():
    return jsonify(message='Home page')  #

#  configuration variable to control redirection
ALLOW_REDIRECTION = False

@main_blueprint.route("/login")
def login():
    
    if ALLOW_REDIRECTION:
        authorization_url, state = flow.authorization_url()
        
        session["state"] = state
        return redirect(authorization_url)
    else:
        authorization_url, _ = flow.authorization_url()
        print(f"Authorization URL: {authorization_url}")
        return jsonify(message='Redirection disabled for testing', authorization_url=authorization_url)

@main_blueprint.route("/callback")
def callback():
    if ALLOW_REDIRECTION:
        flow.fetch_token(authorization_response=request.url)

        if not session["state"] == request.args["state"]:
            abort(500)  # State does not match!

        credentials = flow.credentials
        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=google.auth.transport.requests.Request(session=request),
            audience=flow.client_config['client_id']
        )

        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name")
        return jsonify(message='Callback successful')  # Adjust as needed
    else:
        return jsonify(message='Callback processing disabled for testing')

@main_blueprint.route("/logout")
def logout():
    session.clear()
    return jsonify(message='Logged out successfully')





#JWT Login

@main_blueprint.route("/login/JWT", methods=["POST"])
def login_normal():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
       

        # Generate an access token using Flask-JWT-Extended
        access_token = create_access_token(identity=user.username)

        return jsonify(message='Login successful', access_token=access_token), 200
    else:
        return jsonify(message='Invalid credentials'), 401

    
    
@main_blueprint.route('/register', methods=['POST'])
@csrf.exempt
def register():
    if request.is_json:
        # If the request is in JSON format, extract data
        data = request.get_json()

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not all([username, email, password]):
            return jsonify({'error': 'Incomplete JSON data'}), 400
        
         # Check if the username is already taken
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            return jsonify({'error': 'Username already taken'}), 400

        # Check if the email is already used
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            return jsonify({'error': 'Email already used'}), 400

        # Validate the input data as needed 

        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(
            username=username,
            email=email,
            password_hash=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        # Assuming registration is successful
        response_data = {
            'message': 'Account created successfully! You can now log in.',
        }
        return jsonify(response_data), 201  # Use the appropriate status code

    return jsonify({'error': 'Invalid request format'}), 400  # JSON response for non-JSON requests



@main_blueprint.route('/create_event', methods=['POST'])
@jwt_required()
@csrf.exempt
def create_event():
    form = EventForm()

    # Get the identity (username) from the JWT token
    username = get_jwt_identity()

  
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(message='You need to login first'), 404

    if form.validate_on_submit():
        try:
            event = Event(
                title=form.title.data,
                description=form.description.data,
                date=form.date.data,
                location=form.location.data,
                category=form.category.data,
                image=form.image.data,
                tickets_available=form.tickets_available.data,
                ticket_price=form.ticket_price.data,
                user_id=user.id

            )

            db.session.add(event)
            db.session.commit()

            return jsonify(message='Event created successfully!'), 201
        except Exception as e:
            return jsonify(message=f'Error creating event: {str(e)}'), 500

    return jsonify(errors=form.errors), 400


@main_blueprint.route('/bookmark/<int:event_id>', methods=['POST'])
@jwt_required()
def bookmark_event(event_id):
    # Get the current user
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(message='User not found.'), 404

    try:
        event = Event.query.get_or_404(event_id)
    except:
        return jsonify(message=f'Event with ID {event_id} not found.'), 404

    # Check if the event is already bookmarked
    if Bookmark.query.filter_by(user_id=user.id, event_id=event_id).first():
        return jsonify(message='Event is already bookmarked.'), 200
    else:
        # Bookmark the event
        bookmark = Bookmark(user_id=user.id, event_id=event_id)
        db.session.add(bookmark)
        db.session.commit()
        return jsonify(message='Event bookmarked successfully!'), 201

from flask_jwt_extended import jwt_required, get_jwt_identity

@main_blueprint.route('/bookmarked_events')
@jwt_required()
def bookmarked_events():
    # Get the identity (username) from the JWT token
    username = get_jwt_identity()

    
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify(message='You need to connect first'), 404

    # Access the bookmarks for the current user
    bookmarked_events = Event.query.join(Bookmark).filter_by(user_id=user.id).all()


    # Prepare the response
    events_data = [{
        'title': event.title,
        'description': event.description,
        'date': event.date.isoformat(),
        'location': event.location,
        'category': event.category,
        'image': event.image,
    } for event in bookmarked_events]

    return jsonify(events=events_data)


from flask import jsonify, request, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from .models import db, Event, Participant

@main_blueprint.route('/purchase_ticket/<int:event_id>', methods=['POST'])
@jwt_required()
def purchase_ticket(event_id):
    username = get_jwt_identity()
    
    # Check if user exists
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify(message='User not found'), 404

    event = Event.query.get_or_404(event_id)

    # Parse the number of tickets to purchase from the request
    try:
        num_tickets = int(request.json.get('num_tickets', 1))
        if num_tickets <= 0:
            raise ValueError("Number of tickets must be greater than zero")
    except ValueError:
        return jsonify(message='Invalid input for number of tickets. Please provide a positive integer.'), 400

    # Check if tickets are available
    if event.tickets_available < num_tickets:
        return jsonify(message=f'Not enough tickets available for this event. Available: {event.tickets_available}'), 400


    participant = Participant.query.filter_by(user_id= user.id, event_id=event_id).first()


    # Deduct the number of tickets from available tickets
    event.tickets_available -= num_tickets

    # Update the participant entry or create a new one
    if participant:
        participant.num_tickets_purchased += num_tickets
    else:
        participant = Participant(user_id= user.id, event_id=event_id, num_tickets_purchased=num_tickets)
        db.session.add(participant)

    db.session.commit()

    return jsonify(message=f'{num_tickets} ticket(s) purchased successfully!'), 201


@main_blueprint.route('/events', methods=['GET'])
def get_events():
    events = Event.query.all()

    events_data = [{
        "title": event.title,
        "description": event.description,
        "date": event.date.isoformat(),
        "location": event.location,
        "category": event.category,
        "image": event.image,
        "tickets_available": event.tickets_available,
        "ticket_price":event.ticket_price
    } for event in events]

    return jsonify(events_data)

@main_blueprint.route('/search_event', methods=['GET'])

def search_event():
    title = request.args.get('title')

    if not title:
        return jsonify({'error': 'Please enter a title to search.'}), 400

    event = Event.query.filter_by(title=title).first()

    if not event:
        return jsonify({'error': 'Event not found!'}), 404

    event_details = {
        'title': event.title,
        'description': event.description,
        'date': event.date.isoformat(),
        'location': event.location,
        'category': event.category,
        'image': event.image,
        "tickets_available": event.tickets_available,
        "ticket_price":event.ticket_price
    }

    return jsonify(event_details)