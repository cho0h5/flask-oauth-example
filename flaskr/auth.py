import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

import google_auth_oauthlib
import requests
import os
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"]
GOOGLE_CLIENT_ID = "686310932762-ddndseck2m0kdajccc4v8gef51ahil5q.apps.googleusercontent.com"

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# REDIRECT_URI = "http://127.0.0.1:5000/auth/oauth2callback"
REDIRECT_URI = "http://cho0h5.iptime.org:5000/auth/oauth2callback"

flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
    CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI)

bp = Blueprint('auth', __name__, url_prefix='/auth')

def register(google_id, user_id):
    db = get_db()
    
    db.execute(
        'INSERT INTO user (google_id, user_id) VALUES (?, ?)',
        (google_id, user_id)
    )
    db.commit()

@bp.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@bp.route('/oauth2callback')
def oauth2callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    google_id = id_info.get("sub")
    user_id = id_info.get("name")

    db = get_db()
    if db.execute(
            'SELECT user_id FROM user WHERE google_id = ?', (google_id,)
        ).fetchone() is None:
        register(google_id, user_id)

    session["google_id"] = google_id
    session["user_id"] = user_id
    
    return redirect(url_for('index'))


@bp.before_app_request
def load_logged_in_user():
    google_id = session.get('google_id')

    if google_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE google_id = ?', (google_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view