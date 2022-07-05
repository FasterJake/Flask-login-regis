"""Flask app that renders my hmtl and css files
and has an error function built in to do things
with the html"""
# Imports flask and datetime
import collections

from datetime import datetime
from flask import Flask, render_template, url_for, redirect
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError
from string import punctuation
import os


# Sets app and the first template to Flask as __name__
# to search the template folder at default
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
SECRET_KEY = os.urandom(32)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "SECRET_KEY"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(18), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=4, max=15)]
                           , render_kw={"placeholder": "Please enter username"})

    password = PasswordField('Password', validators=[DataRequired(), Length(min=12, max=25)],
                             render_kw={"placeholder": "Enter a password"})

    submit = SubmitField('Register')

    while True:
        if (any(char.islower() for char in password)
                and any(char.isupper() for char in password)
                and any(char.isdigit() for char in password)
                and any(char in punctuation for char in password)):

            print("Password is correct")

        else:
            print("Needs at least 1 upper and lowercase letter and 1 number and special character")
        break

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                print('It seems there are two of you, make another one.'))


class LoginForm(FlaskForm):
    username = StringField(validators=[
        DataRequired(), Length(min=4, max=15)], render_kw={
        "placeholder": "Enter that username"})

    password = PasswordField(validators=[
        DataRequired(), Length(min=12, max=15)], render_kw={
        "placeholder": "Enter your secret "})

    submit = SubmitField('Login')



@app.route('/')
@login_required
def logging_in():
    return render_template('authenicationpage.html')


# Sets the route to redirect here, and use the html file
# specified as the "homepage" as well as return the current date
@app.route('/scanlanjake_lab6')
@login_required
def homepage():
    """Function to read or render the template html
    and also get the current date"""
    return render_template("scanlanjake_lab6.html", datetime=str(datetime.now()))


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("homepage"))
    return render_template("login.html", form=form)


@app.route("/registration", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))
    return render_template("registration.html", form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# If name is main(as in if main is name essentially)
# then app will run and set debug to true so that the
# program or file can be edited live
if __name__ == "__main__":
    app.run(debug=True)
