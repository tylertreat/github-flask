# -*- coding: utf-8 -*-
"""
    GitHub-Flask
    ============

    Authenticate users in your Flask app with GitHub.

"""
import logging
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode
from functools import wraps

from httplib2 import Http
from flask import redirect, request, json

__version__ = '0.3.4'

logger = logging.getLogger(__name__)


class GitHubError(Exception):
    """Raised if a request fails to the GitHub API."""

    def __str__(self):
        try:
            message = self.response['message']
        except Exception:
            message = None
        return "%s: %s" % (self.response.status, message)

    @property
    def response(self):
        """The response object for the request."""
        return self.args[0]


class GitHub(object):
    """
    Provides decorators for authenticating users with GitHub within a Flask
    application. Helper methods are also provided interacting with GitHub API.

    """
    BASE_URL = 'https://api.github.com/'
    BASE_AUTH_URL = 'https://github.com/login/oauth/'

    def __init__(self, app=None):
        if app is not None:
            self.app = app
            self.init_app(self.app)
        else:
            self.app = None

    def init_app(self, app):
        self.client_id = app.config['GITHUB_CLIENT_ID']
        self.client_secret = app.config['GITHUB_CLIENT_SECRET']
        self.callback_url = app.config['GITHUB_CALLBACK_URL']
        self.base_url = app.config.get('GITHUB_BASE_URL', self.BASE_URL)
        self.http = Http()

    def access_token_getter(self, f):
        """
        Registers a function as the access_token getter. Must return the
        access_token used to make requests to GitHub on the user's behalf.

        """
        self.get_access_token = f
        return f

    def get_access_token(self):
        raise NotImplementedError

    def authorize(self, scope=None):
        """
        Redirect to GitHub and request access to a user's data.

        """
        logger.debug("Called authorize()")
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.callback_url,
        }
        if scope is not None:
            params['scope'] = scope

        url = self.BASE_AUTH_URL + 'authorize?' + urlencode(params)
        logger.debug("Redirecting to %s", url)
        return redirect(url)

    def authorized_handler(self, f):
        """
        Decorator for the route that is used as the callback for authorizing
        with GitHub. This callback URL can be set in the settings for the app
        or passed in during authorization.

        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'code' in request.args:
                data = self._handle_response()
            else:
                data = self._handle_invalid_response()
            return f(*((data,) + args), **kwargs)
        return decorated

    def _handle_response(self):
        """
        Handles response after the redirect to GitHub. This response
        determines if the user has allowed the this application access. If we
        were then we send a POST request for the access_key used to
        authenticate requests to GitHub.

        """
        logger.debug("Handling response from GitHub")
        params = {
            'code': request.args.get('code'),
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        params = json.dumps(params)
        url = self.BASE_AUTH_URL + 'access_token'
        logger.debug("POSTing to %s", url)
        logger.debug(params)
        resp, content = self.http.request(
            url, method='POST', body=params,
            headers={'Content-Type': 'application/json'})
        if resp.status != 200:
            return None
        data = json.loads(content)
        logger.debug("response.content = %s", content)
        return data.get('access_token')

    def _handle_invalid_response(self):
        pass

    def raw_request(self, method, resource, headers=None, body=None):
        """
        Makes a HTTP request and returns a tuple consisting of the HTTP
        response and content.

        """
        if not headers:
            headers = {}

        # TODO: Safely add the access_token parameter.
        url = '%s%s?access_token=%s' % (self.BASE_URL, resource,
                                        self.get_access_token())

        if not body:
            return self.http.request(url, method=method, headers=headers)
        else:
            return self.http.request(url, method=method, headers=headers,
                                     body=body)

    def request(self, method, resource, headers=None, body=None):
        """
        Makes a request to the given endpoint.
        If the content type of the response is JSON, it will be decoded
        automatically and a dictionary will be returned.
        Otherwise the raw content is returned.

        """
        resp, content = self.raw_request(method, resource, headers=headers,
                                         body=body)

        status_code = str(resp.status)

        if status_code.startswith('4'):
            raise GitHubError(resp)

        assert status_code.startswith('2')

        if resp.get('content-type', '').startswith('application/json'):
            return json.loads(content)
        else:
            return content

    def get(self, resource):
        """Shortcut for ``request('GET', resource)``."""
        return self.request('GET', resource)

    def post(self, resource, data):
        """Shortcut for ``request('POST', resource)``.
        Use this to make POST request since it will also encode ``data`` to
        'application/json' format."""
        headers = {'Content-Type': 'application/json'}
        data = json.dumps(data)
        return self.request('POST', resource, headers=headers, data=data)

    def head(self, resource):
        return self.request('HEAD', resource)

    def patch(self, resource):
        return self.request('PATCH', resource)

    def put(self, resource):
        return self.request('PUT', resource)

    def delete(self, resource):
        return self.request('DELETE', resource)

