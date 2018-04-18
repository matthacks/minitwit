from __future__ import print_function
import sys
# -*- coding: utf-8 -*-
"""
    mt_api
    ~~~~~~~~

    A REST API for a microblogging application written with Flask and sqlite3.

    :copyright: (c) 2015 by Armin Ronacher
    :license: BSD, see LICENSE for more details.

    Changes made in 2018 by Matt Corrente
"""
import datetime
import time
from cassandra.cluster import Cluster
from cassandra.query import dict_factory
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack, jsonify
from flask_basicauth import BasicAuth
from werkzeug import check_password_hash, generate_password_hash

# configuration
DATABASE = '/tmp/minitwit_api.db'
PER_PAGE = 30
DEBUG = False
SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'

# create our little application :)
app = Flask('minitwit_api')
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

# Subclass basic_auth and override check_credentials method
class MyAuth(BasicAuth):
    authorized_username = '';

    def check_credentials(self, username, password):
        """Logs the user in."""
        user = query_db('select * from minitwit.user where username = \''+ username +'\'')
        if  len(user.current_rows) == 0:
            error = 'Invalid username'
        elif not check_password_hash(user[0]['pw_hash'],
                                     password):
            error = 'Invalid password'
        else:
            self.authorized_username = username;
            return True
        self.authorized_username = ''
        abort(401)

basic_auth = MyAuth(app)

# ------------------------------------------------------------------------------
# MINITWIT API
# ------------------------------------------------------------------------------

@app.route('/minitwit/api/timeline/public', methods=['GET'])
def public_timeline_api():
    """Displays all tweets in the database."""
    messages=query_db('''
        select * from minitwit.message
    ''')
    data = list()
    print(messages[0], file=sys.stderr)
    for message in messages:
        dict_message = dict(message)
        data.append(dict_message)
    return jsonify(data), 200

@app.route('/minitwit/api/timeline/public/<username>', methods=['GET'])
def user_timeline_api(username):
    """Display's a users tweets."""

    profile_user = query_db('select username from minitwit.user where username = \'' + username + '\'')
    if profile_user is None:
        abort(404)
    followed = False

    data = list()
    # get all of the message_id's for a given user
    followers = query_db('select whom from minitwit.user where username = \'' + username + '\'')
    if  len(followers.current_rows) is not 0 and followers[0]['whom'] is not None:
        items = []
        for x in followers[0]['whom']:
            x = x.encode('utf-8')
            items.append(x)
        items = tuple(items)
        if len(items) == 1:
            items = '(\'' + items[0] + '\')'
        q = 'select * from minitwit.message where username in ' + str(items)
        print(q, file=sys.stderr)

        messages=query_db(q)
        for message in messages:
            dict_message = dict(message)
            data.append(dict_message)
    return jsonify(data), 200

@app.route('/minitwit/api/timeline/personal', methods=['GET'])
@basic_auth.required
def personal_timeline_api():
    """Displays the authenticated user's timeline."""

    data = list()
    # get all of the message_id's for a given user
    followers = query_db('select whom from minitwit.user where username = \'' + basic_auth.authorized_username + '\'')
    if  len(followers.current_rows) is not 0 and followers[0]['whom'] is not None:
        items = []
        for x in followers[0]['whom']:
            x = x.encode('utf-8')
            items.append(x)
        items = tuple(items)
        if len(items) == 1:
            items = '(\'' + items[0] + '\')'
        q = 'select * from minitwit.message where username in ' + str(items)
        print(q, file=sys.stderr)

        messages=query_db(q)
        for message in messages:
            dict_message = dict(message)
            data.append(dict_message)
    return jsonify(data), 200


@app.route('/minitwit/api/timeline/personal', methods=['POST'])
@basic_auth.required
def add_message_api():

    """Registers a new message for the user."""
    content = request.get_json()
    if content['text']:
        email = query_db('select email from minitwit.user where username = \'' + basic_auth.authorized_username + '\'')
        q = 'insert into minitwit.message (username, email, text, pub_date) values (\'' + basic_auth.authorized_username + '\', \'' + email[0]['email'] + '\', \'' + content['text'] + '\', ' + str(time.time()) + ')'
        print(q, file=sys.stderr)
        query_db(q)
        return generate_success_json('Your message was recorded', 200)
    else:
        return generate_error_json('Unprocessible Entity. Cannot create a message without any text.', 422)

@app.route('/minitwit/api/following', methods=['GET'])
@basic_auth.required
def personal_followers_api():
    """Displays all followed users of authenticated user."""
    content = request.get_json()

    data = list()
    followers=query_db('select whom from minitwit.user where username = \'' + basic_auth.authorized_username + '\' ')
    if  len(followers.current_rows) is not 0 and followers[0]['whom'] is not None:
        names = followers[0]['whom']
        for name in names:
            dict_message = dict({'username': name})
            data.append(dict_message)
        print(data, file=sys.stderr)

    return jsonify(data), 200

@app.route('/minitwit/api/following', methods=['PUT'])
@basic_auth.required
def follow_user_api():
    content = request.get_json()
    """Adds the authenticated user as follower of the given user."""
    username = content['username']
    if (len(query_db('select * from minitwit.user where username = \''+ username +'\'').current_rows) is 0):
        return generate_error_json("Unprocessible Entity. Provided username does not exist.", 422)
    if username == basic_auth.authorized_username:
        return generate_error_json("Unprocessible Entity. You cannot follow yourself.", 422)
    query_db('update minitwit.user set whom = whom + [\''+ username +'\'] where username = \'' + basic_auth.authorized_username + '\'')
    return generate_success_json('You are now following %s' % username, 201)


@app.route('/minitwit/api/following', methods=['DELETE'])
@basic_auth.required
def unfollow_user_api():
    content = request.get_json()
    """Adds the authenticated user as follower of the given user."""
    username = content['username']
    if (len(query_db('select * from minitwit.user where username = \''+ username +'\'').current_rows) is 0):
        return generate_error_json("Unprocessible Entity. Provided username does not exist.", 422)

    query_db('update minitwit.user set whom = whom - [\''+ username +'\'] where username = \'' + basic_auth.authorized_username + '\'')
    return generate_success_json('You are no longer following %s' % username, 200)

@app.route('/minitwit/api/register', methods=['POST'])
def register_api():
    """Registers the user."""
    content = request.get_json()
    if not content['username']:
        error = 'You have to enter a username.'
    elif not content['email'] or \
            '@' not in content['email']:
        error = 'You have to enter a valid email address.'
    elif not content['password']:
        error = 'You have to enter a password.'
    elif content['password'] != content['password2']:
        error = 'The two passwords do not match.'
    elif (len(query_db('select * from minitwit.user where username = \''+ content['username'] +'\'').current_rows) is not 0):
        error = 'The username is already taken.'
    else:
        db = get_db()
        db.execute(('insert into minitwit.user (username, email, pw_hash, whom) values (\'' + content['username'] + '\', \'' + content['email'] + '\', \'' + generate_password_hash(content['password']) + '\', [\''+ content['username'] +'\'])'))
        return generate_success_json('Account successfully registered', 201)
    return generate_error_json('Unprocessible Entity. ' + error, 422)

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------
def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'cassandra_db'):
        cluster = Cluster()
        top.cassandra_db = cluster.connect('minitwit')
        top.cassandra_db.row_factory = dict_factory
    return top.cassandra_db

@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'cassandra_db'):
        top.cassandra_db.shutdown()


def init_db():
    """Initializes the database."""
    db = get_db()
    with app.open_resource('schema.cql', mode='r') as f:
        queries = f.read().split(';')
        queries.pop() # delete the EOF element
        for q in queries:
            db.execute(q)

@app.cli.command('initdb')
def initdb_command():
    """Creates the database tables."""
    init_db()
    print('Initialized the database.')

def populate_db():
    """Populate the database with test data."""
    db = get_db()
    with app.open_resource('population.cql', mode='r') as f:
        queries = f.read().split(';')
        queries.pop() # delete the EOF element
        for q in queries:
            db.execute(q)

@app.cli.command('populatedb')
def populatedb_command():
    """populates the database tables with test data."""
    populate_db()
    print('Populated the database.')


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query)
    # print(cur)
    #rv = cur.fetchall()
    #return (rv[0] if rv else None) if one else rv
    return cur

def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where username = ?',
                  [username], one=True)
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'https://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

# ------------------------------------------------------------------------------
# Custom Error/Success Messages
# ------------------------------------------------------------------------------
def generate_error_json(message, errorNum):
    data = dict()
    data["message"] = message
    data["code"] = errorNum
    return jsonify(error=data), errorNum

def generate_success_json(message, statusNum):
    data = dict()
    data["message"] = message
    data["code"] = statusNum
    return jsonify(data), statusNum

@app.errorhandler(500)
def internal_server_error(e):
    data = dict()
    data["message"] = "Internal Server Error. Check that all your JSON parameters are correct."
    data["code"] = 500
    return jsonify(error=data), 500

@app.errorhandler(400)
def bad_request_error(e):
    data = dict()
    data["message"] = "Bad Request. The browser (or proxy) sent a request that this server could not understand."
    data["code"] = 400
    return jsonify(error=data), 400

@app.errorhandler(401)
def unauthorized_error(e):
    data = dict()
    data["message"] = "Unauthorized. Check credentials and try again."
    data["code"] = 401
    return jsonify(error=data), 401

@app.errorhandler(404)
def page_not_found(e):
    data = dict()
    data["message"] = "404 Not Found. The requested URL was not found on the server."
    data["code"] = 404
    return jsonify(error=data), 404

@app.errorhandler(405)
def method_not_allowed_error(e):
    data = dict()
    data["message"] = "405 Method Not Allowed."
    data["code"] = 405
    return jsonify(error=data), 405

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url
