from flask import current_app
from flask.cli import with_appcontext
from .models import db, User
import logging
import click


@click.command(name='create-sample-user')

@with_appcontext
def create_sample_user():
    existing_user = User.query.filter_by(username='sample_user').first()

    if not existing_user:
        sample_user = User(
            username='sample_user',
            email='sample@example.com',
            password_hash='hashed_password'  # Replace with the hashed password
        )

        db.session.add(sample_user)
        db.session.commit()

        logging.info("Sample user created successfully.")
    else:
        logging.info("Sample user already exists.")
