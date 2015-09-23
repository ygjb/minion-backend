#!/usr/bin/env python
from flask import jsonify

from minion.backend.app import app
from minion.backend.views.base import api_guard
from minion.backend.models import Plugin


# API Methods to manage plugins

#
# Return a list of available plugins
#
#  GET /plugins
#

@app.route("/plugins")
@api_guard
def get_plugins():
    return jsonify(success=True, plugins=[plugin['descriptor'] for plugin in Plugin.plugins.values()])