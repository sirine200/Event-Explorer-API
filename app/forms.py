# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateTimeField, SubmitField, PasswordField, IntegerField, FloatField
from wtforms.validators import DataRequired, Email, Length, EqualTo,Optional

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=6), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')

    def validate(self):
        # Call the base class validation
        if not super(RegistrationForm, self).validate():
            return False

        # Additional validation for JSON requests
        if not self.confirm_password.data == self.password.data:
            self.confirm_password.errors.append('Passwords must match')
            return False

        return True
    
class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = DateTimeField('Date (YYYY-MM-DD HH:MM)', format='%Y-%m-%d %H:%M', validators=[DataRequired()])
    location = StringField('Location')
    category = StringField('Category')
    image = StringField('Image URL')
    tickets_available = IntegerField('Tickets Available', validators=[Optional()])
    ticket_price = FloatField('Ticket Price', validators=[Optional()])
    submit = SubmitField('Create Event')

class BookmarkForm(FlaskForm):
    submit = SubmitField('Bookmark Event')
