#!/usr/bin/env python

import calendar
import datetime
import uuid
from flask import jsonify, request

from minion.backend.app import app
from minion.backend.models import db, Group, User, Site
from minion.backend.views.base import api_guard
from minion.backend.views.groups import _check_group_exists

#xxx
import json


# XXX needed?
def _find_sites_for_user_by_group_name(email, group_name):
    """ Find all sites that user has access to in a
    given group. """
    group = Group.get_group(group_name)
    user = User.get_user(email)
    if not user or not group:
        return []
    if not user in group.users:
        return []
    return map(lambda x: x.url, group.sites)


# XXX - this function should be deleted as Group.add_user(username) / Group.remove_user(username) will maintain these
# def update_group_association(old_email, new_email):
#    """ Update all associations with the old email
#    to the new email. """
#
#    groups.update({'users': old_email},
#        {'$set': {'users.$': new_email}},
#        upsert=False,
#        multi=True)
#
#def remove_group_association(email):
#    """ Remove all associations with the recipient.
#    This is required for a declined invitation
#    or when a user is banned or deleted.
#
#    In case we have found a user in the same
#    membership list multiple time (should not
#    happen), we better to pull all the
#    occurences out. Hence why we use
#    $pull over $pop."""
#
#    groups.update({'users': email},
#        {'$pull': {'users': email}},
#        upsert=False,
#        multi=True)

def sanitize_user(user):
    return user.dict()

# API Methods to manage users

@app.route('/login', methods=['PUT'])
@api_guard('application/json')
def login_user():
    email = request.json['email']
    user = User.get_user(email)
    if user:
        if user.status == 'active':
            timestamp = datetime.datetime.utcnow()
            user.last_login = timestamp
            db.session.commit()
            return jsonify(success=True, user=sanitize_user(user))
        else:
            return jsonify(success=False, reason=user.status)
    else:
        return jsonify(success=False, reason='user-does-not-exist')

@app.route('/users/<email>', methods=['GET'])
@api_guard
def get_user(email):
    email = email.lower()
    user = User.get_user(email)
    if not user:
        return jsonify(success=False, reason='no-such-user')
    return jsonify(success=True, user=sanitize_user(user))

#
# Create a new user
#
#  POST /users
#
# Expects a partially filled out user record
#
#  { email: "foo@bar",
#    name: "Foo",
#    groups: ["foo"],
#    role: "user" }
#
# Optionally, the POST accepts creating user via invitations by adding
# 'invitation', 'url' and an optional 'sender' to the json input above.
# Returns the full user record
#
#  { "success": true
#    "user": { "created": 1371044067,
#              "groups": ["foo"],
#              "role": "user",
#              "id": "51f8417d-f7b0-48d1-8c18-dbf5e06c3261",
#              "name": "Foo",
#              "email": "foo@bar" } }
#

@app.route('/users', methods=['POST'])
@api_guard('application/json')
def create_user():
    user = request.json
    # Verify incoming user: email must not exist yet, groups must exist, role must exist
    if User.get_user(user["email"]) is not None:
        return jsonify(success=False, reason='user-already-exists')

    for group_name in user.get('groups', []):
        if not Group.get_group(group_name):
            return jsonify(success=False, reason='unknown-group')

    if user.get("role") not in ("user", "administrator"):
        return jsonify(success=False, reason="invalid-role")

    new_user = User(user.get('name'), user['email'])
    new_user.created = datetime.datetime.utcnow()
    new_user.status = 'invited' if user.get('invitation') else 'active'
    new_user.role = user['role']
    new_user.last_login = None
    api_key = str(uuid.uuid4())

    db.session.add(new_user)
    db.session.commit()

    for group_name in user.get('groups', []):
        new_user.groups.append(Group.get_group(group_name))

    db.session.commit()
    return jsonify(success=True, user=sanitize_user(new_user))

#
# Expects a partially filled out user as POST data. The user with the
# specified user_email (in the URL) will be updated.
#
# Fields that can be changed:
#
#  name
#  role
#  groups
#  status
#
# Fields that are specified in the new user object will replace those in
# the existing user object.
#
# Returns the full user record.
#

@app.route('/users/<user_email>', methods=['POST'])
@api_guard
def update_user(user_email):
    new_user = request.json
    # Verify the incoming user: user must exist, groups must exist, role must exist

    old_user = User.get_user(user_email)
    if old_user is None:
        return jsonify(success=False, reason='unknown-user')

    if 'groups' in new_user:
        for group_name in new_user.get('groups', []):
            if not Group.get_group(group_name):
                return jsonify(success=False, reason='unknown-group')
    if 'role' in new_user:
        if new_user["role"] not in ("user", "administrator"):
            return jsonify(success=False, reason="invalid-role")
    if 'status' in new_user:
        if new_user['status'] not in ('active', 'banned'):
            return jsonify(success=False, reason='unknown-status-option')

    # Update the group memberships
    if 'groups' in new_user:
        #clear all groups
        for group in old_user.groups:
            old_user.groups.remove(group)
        #add new groups
        for group in new_user.get('groups', []):
            old_user.groups.append(Group.get_group(group))
    
    # Modify the user
    changes = {}
    if 'name' in new_user:
        old_user.name = new_user['name']
    if 'role' in new_user:
        old_user.role = new_user['role']
        
    if 'status' in new_user:
        old_user.status = new_user['status']

    db.session.commit()
    
    # Return the updated user
    user = User.get_user(user_email)
    if not user:
        return jsonify(success=False, reason='unknown-user')
    return jsonify(success=True, user=sanitize_user(user))

#
# Retrieve all users in minion
#
#  GET /users
#
# Returns a list of users
#
#  [{ 'id': 'b263bdc6-8692-4ace-aa8b-922b9ec0fc37',
#     'email': 'someone@somedomain',
#     'role': 'user',
#     'sites': ['https://www.mozilla.com'],
#     'groups': ['mozilla', 'key-initiatives'] },
#    ...]
#

@app.route('/users', methods=['GET'])
@api_guard
def list_users():
    userz = map(lambda x : x.dict(), User.query.all())
    return jsonify(success=True, users=userz)

#
# Delete a user
#
#  DELETE /users/{email}
#

@app.route('/users/<user_email>', methods=['DELETE'])
@api_guard
def delete_user(user_email):
    user = User.get_user(user_email)
    if not user:
        return jsonify(success=False, reason='no-such-user')
    # Remove the user
    db.session.delete(user)
    db.session.commit()
    return jsonify(success=True)
