#!/usr/bin/env python

import calendar
import datetime
import uuid
from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.models import db, Group, User, Site
from minion.backend.views.base import api_guard

def _check_group_exists(group_name):
    return Group.get_group(group_name) is not None

def sanitize_group(group):
    return group.dict()

# Retrieve all groups in minion
#
#  GET /groups
#
# Returns a list of groups
#
#  [{ 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#     'created': 7261728192,
#     'name': 'someone@somedomain',
#     'description': 'user' },
#    ...]
#

@app.route('/groups', methods=['GET'])
@api_guard
def list_groups():
    return jsonify(success=True, groups=[sanitize_group(group) for group in Group.query.all()])

#
# Expects a partially filled out site as POST data:
#
#  POST /groups
#
#  { "name": "mozilla",
#    "description": "Mozilla Web Properties" }
#
# Returns the full group record including the generated id:
#
#  { "success": True,
#    "group": { "id': "b263bdc6-8692-4ace-aa8b-922b9ec0fc37",
#               "created": 7262918293,
#               "name': "mozilla",
#               "description": "Mozilla Web Properties" } }
#
# Or returns an error:
#
#  { 'success': False, 'reason': 'group-already-exists' }
#

@app.route('/groups', methods=['POST'])
@api_guard('application/json')
def create_group():
    group = request.json


    # perform validations on incoming data; issue#132
    if not group.get('name'):
        return jsonify(success=False, reason='name-field-is-required')

    userz = group.get('users', [])
    sitez = group.get('sites', [])

    if userz:
        for user in userz:
            if not User.get_user(user):
                return jsonify(success=False, reason='user %s does not exist'%user)
    if sitez:
        for site in sitez:
            if not Site.get_site_by_url(site):
                return jsonify(success=False, reason='site %s does not exist'%site)

    if Group.get_group(group['name']) is not None:
        return jsonify(success=False, reason='group-already-exists')

    # post-validation
    # XXX - this is a horrible hack, we should grab the default admin user / admin group instead, not just use the first user/group in the list!!!!
    admin_user = User.query.all()[0]
    admin_group = None
    if len(Group.query.all()) > 0:
        admin_group = Group.query.all()[0]
    new_group = Group(group['name'], admin_user.email, admin_group)
    new_group.created = datetime.datetime.utcnow()
    new_group.description = group.get('description', "")

    db.session.add(new_group)
    
    for user in userz:
        new_group.users.append(User.get_user(user))
        

    for site in sitez:
        new_group.sites.append(Site.get_site_by_url(site))

    db.session.commit()

    new_group = Group.get_group(group['name'])
    return jsonify(success=True, group=sanitize_group(new_group))

@app.route('/groups/<group_name>', methods=['GET'])
@api_guard
def get_group(group_name):
    group = Group.get_group(group_name)
    if not group:
        return jsonify(success=False, reason='no-such-group')
    return jsonify(success=True, group=sanitize_group(group))

#
# Delete the named group
#
#  DELETE /groups/:group_name
#

@app.route('/groups/<group_name>', methods=['DELETE'])
@api_guard
def delete_group(group_name):
    group = Group.get_group(group_name)

    if not group:
        return jsonify(success=False, reason='no-such-group')
    db.session.delete(group)
    db.session.commit()
    return jsonify(success=True)

#
# Patch (modify) a group record
#
#  POST /groups/:groupName
#
# Expects a JSON structure that contains patch operations as follows:
#
#  { addSites: ["http://foo.com"],
#    removeSites: ["http://bar.com"],
#    addUsers: ["foo@cheese"],
#    removeUsers: ["bar@bacon"] }
#

#XXX - Verify if this is used anywhere?  the API seems inconsistent?
@app.route('/groups/<group_name>', methods=['PATCH'])
@api_guard('application/json')
def patch_group(group_name):

    patch = request.json

    group = Group.get_group(group_name)
    
    if not group:
        return jsonify(success=False, reason='no-such-group')

    # Process the edits. These can probably be done in one operation.

    for url in patch.get('addSites', []):
        site = Site.get_site_by_url(url)
        if not site:
            return jsonoify(success = false, reason='no-such-site')
        if not site in group.sites:
            group.sites.append(site)

    for url in patch.get('removeSites', []):
        site = Site.get_site_by_url(url)
        if not site:
            return jsonoify(success = false, reason='no-such-site')
        if site in group.sites:
            group.sites.remove(site)
    
    for email in patch.get('addUsers', []):
        user = User.get_user(email)
        if not user:
            return jsonoify(success = false, reason='no-such-user')
        if not user in group.users:
            group.users.append(user)

    for user in patch.get('removeUsers', []):
        user = User.get_user(email)
        if not user:
            return jsonoify(success = false, reason='no-such-user')
        if user in group.users:
            group.users.remove(user)

    db.session.commit()
    group = Group.get_group(group_name)
    return jsonify(success=True, group=sanitize_group(group))

