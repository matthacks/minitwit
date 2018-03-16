# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask and sqlite3.

    :copyright: (c) 2015 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.

    Changes made in 2018 by Matt Corrente
"""

import time
import requests
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash


# configuration
API_BASE_URL='http://127.0.0.1:5000/minitwit/api/'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit')
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = {'username': session['user_id']}


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    return render_template('timeline.html', messages=requests.get(API_BASE_URL + 'timeline/personal', auth=(session['user_id'], session['user_password'])).json())


@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""

    return render_template('timeline.html', messages=requests.get(API_BASE_URL + 'timeline/public').json())


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""

    followed = False
    if g.user:
        # obtain JSON containing list of users that current user is following then check if
        # the user of the displayed profile is in the JSON
        r = requests.get(API_BASE_URL + 'following', auth=(session['user_id'], session['user_password'])).json()
        if r != []:
            for i in r:
                if username == i['username']:
                    followed = True
                    break
    return render_template('timeline.html',  messages=requests.get(API_BASE_URL +
     'timeline/public/' + username).json(),
      followed=followed,
            profile_user={'username': username})


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    r = requests.put(API_BASE_URL + 'following', auth=(session['user_id'], session['user_password']),
    json={"username": username})
    if r.status_code == 201:
        flash('You are now following "%s"' % username)
        return redirect(url_for('user_timeline', username=username))
    else:
        abort(404)


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    r = requests.delete(API_BASE_URL + 'following', auth=(session['user_id'], session['user_password']),
    json={"username": username})
    if r.status_code == 200:
        flash('You are no longer following "%s"' % username)
        return redirect(url_for('user_timeline', username=username))
    else:
        abort(404)


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        r = requests.post(API_BASE_URL + 'timeline/personal', auth=(session['user_id'], session['user_password']),
        json={"text": request.form['text']})
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        r = requests.get(API_BASE_URL + 'timeline/personal', auth=(request.form['username'],request.form['password']))
        if r.status_code == 200:
            flash('You were logged in')
            session['user_id'] = request.form['username']
            session['user_password'] = request.form['password']
            return redirect(url_for('timeline'))
        else:
            error = r.json()['error']['message'];
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        else:
            pword1 = generate_password_hash(request.form['password'])
            r = requests.post(API_BASE_URL + 'register', json={"username": request.form['username'],
            "password": request.form['password'], "password2": request.form['password2'],
            "email": request.form['email']});
            if r.status_code == 201:
                flash('You were successfully registered and can login now')
                return redirect(url_for('login'))
            else:
                error = r.json()['error']['message'];
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url
