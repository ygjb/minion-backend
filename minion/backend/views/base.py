#!/usr/bin/env python

import calendar
import functools
import importlib
import inspect
import json
import pkgutil
import operator

from flask import abort, Flask, jsonify, request, session
from pymongo import MongoClient

from minion.backend.app import app
from minion.backend.models import Plugin
import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.plugins.base import AbstractPlugin

backend_config = backend_utils.backend_config()


def api_guard(*decor_args):
    """ Decorate a view function to be protected by requiring
    a secret key in X-Minion-Backend-Key header for the decorated
    backend API. If 'key' is False or not found in the config file,
    the decorator will assume no protection is needed and will grant
    access to all incoming request.

    """
    def decorator(view):
        @functools.wraps(view)
        def check_session(*args, **kwargs):
            if isinstance(decor_args[0], str):
                if request.headers.get('content-type') != decor_args[0]:
                    abort(415)
            token_in_header = request.headers.get('x-minion-backend-key')
            secret_key = backend_config['api'].get('key')
            if secret_key:
                if token_in_header:
                    if token_in_header == secret_key:
                        return view(*args, **kwargs)
                    else:
                        abort(401)
                else:
                    abort(401)
            return view(*args, **kwargs)
        return check_session

    # the decorator can implicilty take the function being
    # decorated. We must ensure the arg is actually callable.
    # Otherwise, we call the decorator without any argument.
    if len(decor_args) == 1 and callable(decor_args[0]):
        return decorator(decor_args[0])
    else:
        return decorator

#
# Build the plugin registry
#

#
# Build the plugin registry
#

# XX sigh.  we should have a view to force reloading of plugins.
Plugin.load_plugin()
