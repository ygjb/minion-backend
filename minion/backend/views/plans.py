#!/usr/bin/env python

import calendar
import datetime
import functools
import importlib
import uuid

from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard
from minion.backend.models import db, User, Group, Site, Plan, Plugin, Workflow
import json


def _plan_description(plan):
    return {
        'description': plan['description'],
        'name': plan['name'],
        'workflow': plan['workflow'],
        'created' : plan['created'] }

def get_plan_by_plan_name(plan_name):
    return Plan.get_plan(plan_name)

def get_sanitized_plans():
    return [sanitize_plan(_plan_description(plan)) for plan in plans.find()]

def _check_plan_by_email(email, plan_name):
    plan = plans.find_one({'name': plan_name})
    if not plan:
        return False
    sitez = sites.find({'plans': plan_name})
    if sitez.count():
        matches = 0
        for site in sitez:
            groupz = groups.find({'users': email, 'sites': site['url']})
            if groupz.count():
                matches += 1
        return matches

def get_plans_by_email(email):
    user = User.get_user(email)
    plans_by_site = map(lambda x:Site.get_site_by_url(x).plans, user.sites())
    plans = []
    for planlist in plans_by_site:
        for plan in planlist:
            if not plan in plans:
                plans.append(plan)
    return map(lambda x : x.dict(), plans)
    

def permission(view):
    @functools.wraps(view)
    def has_permission(*args, **kwargs):
        email = request.args.get('email')
        if email:
            user = User.get_user(email)
            if not user:
                return jsonify(success=False, reason='User does not exist.')
            if user.role == 'user':
                plan_name = request.view_args['plan_name']
                if not _check_plan_by_email(email, plan_name):
                    return jsonify(success=False, reason="Plan does not exist.")
        return view(*args, **kwargs) # if groupz.count is not zero, or user is admin
    return has_permission

def sanitize_plan(plan):
    return plan.dict()

def _split_plugin_class_name(plugin_class_name):
    e = plugin_class_name.split(".")
    return '.'.join(e[:-1]), e[-1]

def _import_plugin(plugin_class_name):
    package_name, class_name = _split_plugin_class_name(plugin_class_name)
    plugin_module = importlib.import_module(package_name, class_name)
    return getattr(plugin_module, class_name)

def create_workflows_from_json(workflow):
    """ Ensure plan workflow contain valid structure. """
    results = []

    for flow in workflow:
        if not 'plugin_name' in flow:
            return None
        if not 'description' in flow:
            return None
        if not 'configuration' in flow:
            return None

    for flow in workflow:
        wf = Workflow()
        wf.plugin_name = flow['plugin_name']
        wf.configuration = json.dumps(flow['configuration'])
        wf.description = flow['description']
        results.append(wf)
    return results

def _check_plan_exists(plan_name):
    return plans.find_one({'name': plan_name}) is not None

# API Methods to manage plans

#
# Return a list of available plans. Plans are global and not
# limited to a specific user.
#
#  GET /plans
#
# Returns an array of plan:
#
#  { "success": true,
#    "plans": [ { "description": "Run an nmap scan",
#                 "name": "nmap" },
#               ... ] }
#

@app.route("/plans", methods=['GET'])
@api_guard
def get_plans():
    name = request.args.get('name')
    if name:
        plan = Plan.get_plan(name)
        if not plan:
            return jsonify(success=False, reason="no-such-plan")
        else:
            return jsonify(success=True, plans=[plan.dict()])
    else:
        email = request.args.get('email')
        if email:
            plans = get_plans_by_email(email)
        else:
            plans = map(lambda x : x.dict(), Plan.query.all())
        return jsonify(success=True, plans=plans)

#
# Delete an existing plan
#
#  DELETE /plans/<plan_name>
#

@app.route('/plans/<plan_name>', methods=['DELETE'])
@api_guard
def delete_plan(plan_name):
    plan = Plan.get_plan(plan_name)
    if not plan:
        return jsonify(success=False, reason="Plan does not exist.")

    # XX assess the impact of deleting a plan against existing scans?
    db.session.delete(plan)
    db.session.commit()
    return jsonify(success=True)

#
# Create a new plan
#

@app.route("/plans", methods=['POST'])
@api_guard('application/json')
def create_plan():
    plan = request.json

    # Verify incoming plan
    if Plan.get_plan(plan['name']) is not None:
        return jsonify(success=False, reason='plan-already-exists')

    workflows = create_workflows_from_json(plan['workflow'])
    if not workflows:
        return jsonify(success=False, reason='invalid-plan-exists')

    # Create the plan
    new_plan = Plan()
    new_plan.name = plan['name']
    new_plan.description = plan['description']

    db.session.add(new_plan)
    db.session.commit()

    for workflow in workflows:
        db.session.add(workflow)
        new_plan.workflows.append(workflow)
        db.session.commit()

    plan = Plan.get_plan(new_plan.name)
    # Return the new plan
    if not plan:
        return jsonify(success=False)
    return jsonify(success=True, plan=sanitize_plan(plan))

#
# Update a plan
#

@app.route('/plans/<plan_name>', methods=['POST'])
@api_guard
@permission
def update_plan(plan_name):
    plan = Plan.get_plan(plan_name)

    if not plan:
        return jsonify(success=False, reason='no-such-plan')

    new_plan = request.json

    new_workflow = create_workflows_from_json(new_plan['workflow'])
    if not new_workflow:
        return jsonify(success=False, reason='invalid-plan')

    plan.name = new_plan.get("name", plan.name)
    plan.description = new_plan.get("description", plan.description)

    old_flows = map(lambda x: x, plan.workflows)
    for flow in old_flows:
        plan.workflows.remove(flow)    

    for new_flow in new_workflow:
        db.session.add(new_flow)
        plan.workflows.append(new_flow)        
    
    db.session.commit()

    return jsonify(success=True, plan=sanitize_plan(Plan.get_plan(plan.name)))


#
# Return a single plan description. Takes the plan name.
#
#  GET /plans/:plan_name
#
# Returns a JSON structure that contains the complete plan
#
#  { "success": true,
#    "plan": { "description": "Run an nmap scan",
#               "name": "nmap",
#               "workflow": [ { "configuration": {},
#                               "description": "Run the NMAP scanner.",
#                               "plugin": { "version": "0.2",
#                                           "class": "minion.plugins.nmap.NMAPPlugin",
#                                           "weight": "light",
#                                           "name": "NMAP" } } ] }
#

@app.route("/plans/<plan_name>", methods=['GET'])
@api_guard
@permission
def get_plan(plan_name):
    plan = get_plan_by_plan_name(plan_name)
    if not plan:
        return jsonify(success=False, reason="Plan does not exist")
    return jsonify(success=True, plan=sanitize_plan(plan))
        
