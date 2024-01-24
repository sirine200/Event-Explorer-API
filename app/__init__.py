# app/__init__.py
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_oauthlib.client import OAuth
from flask_wtf.csrf import CSRFProtect
import json
from .commands import create_sample_user
from .models import db
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flasgger import Swagger
from flask import render_template





jwt = JWTManager()
login_manager = LoginManager()
oauth = OAuth()
csrf = CSRFProtect()
migrate = Migrate()

with open('client_secrets.json') as f:
    client_secrets = json.load(f)




def create_app():
    app = Flask(__name__)

    # Load configuration from config.py
    app.config.from_pyfile('config.py')
    
    # Set the secret key for the application

    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')

    # Set the SQLALCHEMY_DATABASE_URI configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
    
    # Initialize the JWT extension with the Flask app
    jwt.init_app(app)
    
    # Initialize Flask-Migrate
    migrate.init_app(app, db)
      
    # Initialize Swagger with the Flask app and configure it
    swagger = Swagger(app, template_file='C:/Users/Thinkpad/3D Objects/EventExplorer/swagger.yml')
    
    # Include Swagger UI route
    from flasgger.utils import swag_from

    @app.route('/apidocs')
    @swag_from('C:/Users/Thinkpad/3D Objects/EventExplorer/swagger.yml')
    def apidocs():
     return render_template("C:/Users/Thinkpad/3D Objects/EventExplorer/swagger.yml")
    
    # Able/Disable CSRF protection for the entire application
    app.config['WTF_CSRF_ENABLED'] = False
    
    #DB initialization,
    db.init_app(app)
    
    #Login manager initilization 
    login_manager.init_app(app)
    
    #Oauth initlization
    oauth.init_app(app)
    
    #CSRF Protection initilization
    csrf.init_app(app)

    # Google OAuth2 configuration
    google = oauth.remote_app(
        'google',
        consumer_key=client_secrets['web']['client_id'],
        consumer_secret=client_secrets['web']['client_secret'],
        request_token_params=None,
        base_url='https://www.googleapis.com/oauth2/v1/',
        request_token_url=None,
        access_token_method='POST',
        access_token_url='https://accounts.google.com/o/oauth2/token',
        authorize_url='https://accounts.google.com/o/oauth2/auth',
    )
    # Set the redirect_uri using the setter method
    google.redirect_uri = "http://127.0.0.1:5000/callback"

    # Register blueprints outside the app context
    from .routes import main_blueprint
    app.register_blueprint(main_blueprint)

    @login_manager.user_loader
    def load_user(user_id):
        # Implement the actual user loader based on your User model
        from .models import User
        return User.query.get(int(user_id))

    # Register the CLI command
    app.cli.add_command(create_sample_user)

    return app


# Import at the end to avoid circular import issues
from app.routes import main_blueprint