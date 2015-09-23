#!/usr/bin/env python

import calendar
import datetime
import functools
import json
import uuid
from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.models import db, Scan, Site, Plan, Group, Plugin, User,Session
from minion.backend.views.base import api_guard
from minion.backend.views.plans import sanitize_plan



def permission(view):
    @functools.wraps(view)
    def has_permission(*args, **kwargs):
        email = request.args.get('email')

        # If the task is scheduled by crontab, proceed with the task
        if email == 'cron':
            return view(*args, **kwargs)

        if email:
            user = User.get_user(email)
            if not user:
                return jsonify(success=False, reason='user-does-not-exist')
            scan = Scan.get_scan(kwargs['scan_id'])
            if user.role == 'user':
                # XX really, really fix the Scan :: Site association, but for compat we will do the json dance

                if not Scan.site in user.sites:
                    return jsonify(success=False, reason='not-found')

        return view(*args, **kwargs) # if groupz.count is not zero, or user is admin
    return has_permission

def sanitize_scan(scan):

    result = {
                'id': scan.scan_uuid,
                'meta': json.loads(scan.meta),
                'state': scan.state,
                'configuration':  json.loads(scan.configuration),
                'plan': scan.plan,
                'sessions': map(lambda x : x.dict(), scan.sessions),
    }
    if scan.created:
     result['created'] = calendar.timegm(scan.created.utctimetuple())
    if scan.finished:
     result['finished'] = calendar.timegm(scan.finished.utctimetuple())
    if scan.queued:
     result['queued'] = calendar.timegm(scan.queued.utctimetuple())
    if scan.started:
     result['started'] = calendar.timegm(scan.created.utctimetuple())


    return result

def summarize_scan(scan):
    def _count_issues(scan, severity):
        count = 0
        for session in scan.sessions:
            for issue in session.issues:
                if issue.severity == severity:
                    count += 1
        return count


    summary = { 'id': scan.scan_uuid,
                'meta': json.loads(scan.meta),
                'state': scan.state,
                'configuration':  json.loads(scan.configuration),
                'plan': json.loads(scan.plan),
                'sessions': [ ],
                'issues': { 'critical': _count_issues(scan, 'Critical'),
                            'high': _count_issues(scan, 'High'),
                            'low': _count_issues(scan, 'Low'),
                            'medium': _count_issues(scan, 'Medium'),
                            'info': _count_issues(scan, 'Info') } }

    if scan.created:
     summary['created'] = calendar.timegm(scan.created.utctimetuple())
    if scan.finished:
     summary['finished'] = calendar.timegm(scan.finished.utctimetuple())
    if scan.queued:
     summary['queued'] = calendar.timegm(scan.queued.utctimetuple())
    if scan.started:
     summary['started'] = calendar.timegm(scan.created.utctimetuple())

    for session in scan.sessions:
        summary['sessions'].append({ 'plugin': json.loads(session.plugin),
                                     'id': session.session_uuid,
                                     'state': session.state})
    return summary

# API Methods to manage scans

#
# Return a scan. Returns the full scan including all issues.
#

@app.route("/scans/<scan_id>")
@api_guard
@permission
def get_scan(scan_id):
    scan = Scan.get_scan(scan_id)
    if not scan:
        return jsonify(success=False, reason='not-found')
    return jsonify(success=True, scan=sanitize_scan(scan))

#
# Return a scan summary. Returns just the basic info about a scan
# and no issues. Also includes a summary of found issues. (count)
#

@app.route("/scans/<scan_id>/summary")
@api_guard
@permission
def get_scan_summary(scan_id):
    Scan.get_scan(scan_id)
    if not scan:
        return jsonify(success=False, reason='not-found')
    return jsonify(success=True, summary=summarize_scan(sanitize_scan(scan)))

#
# Create a scan by POSTING a configuration to the /scan
# resource. The configuration looks like this:
#
#   {
#      "plan": "tickle",
#      "configuration": {
#        "target": "http://foo"
#      }
#   }
#

@app.route("/scans", methods=["POST"])
@api_guard('application/json')
@permission
def post_scan_create():
    # try to decode the configuration
    configuration = request.json
    
    # See if the plan exists
    plan = Plan.get_plan(configuration['plan'])
    if not plan:
        return jsonify(success=False)
    # Merge the configuration
    # Create a scan object

    scan = Scan()

    scan.meta = json.dumps({ "user": configuration['user'], "tags": [] } )

    scan.configuration = json.dumps(configuration['configuration'])
    scan.site = Site.get_site_by_url(configuration['configuration']['target'])

    scan.plan = json.dumps( { "name": plan.name, "revision": 0 })

    db.session.add(scan)
    db.session.commit()
    for step in plan.workflows:

        session_configuration = {}
        if step.configuration:
         session_configuration = json.loads(step.configuration)
        session_configuration.update(configuration['configuration'])


        session = Session()
        session.configuration = json.dumps(session_configuration)
        session.description = step.description

        session.plugin = json.dumps(Plugin.plugins[step.plugin_name]['descriptor'])

        scan.sessions.append(session)
        db.session.add(session)
        db.session.commit()

    db.session.commit()

    return jsonify(success=True, scan=sanitize_scan(scan))

@app.route("/scans", methods=["GET"])
@permission
def get_scans():
    limit = request.args.get('limit', 3)
    if limit: limit = int(limit)
    site_id = request.args.get('site_id')
    
    site = Site.get_site(site_id)

    if not site:
        return jsonify(success=False, reason='no-such-site')


    scanlist = list(site.scans)
    scanlist.sort(key=lambda x : x.created, reverse = True)

    scanlist = scanlist[:limit]

    results = map(lambda x : summarize_scan(x), scanlist)

    return jsonify(success=True, scans=results)



@app.route("/scans/<scan_id>/control", methods=["PUT"])
@api_guard
@permission
def put_scan_control(scan_id):
    # Find the scan
    scan = Scan.get_scan(scan_id)
    if not scan:
        return jsonify(success=False, error='no-such-scan')
    # Check if the state is valid
    state = request.data
    if state not in ('START', 'STOP'):
        return jsonify(success=False, error='unknown-state')


    # Handle start
    if state == 'START':
        if scan.state != 'CREATED':
            return jsonify(success=False, error='invalid-state-transition')


        scan.state = "QUEUED"
        scan.queued = datetime.datetime.utcnow()
        # Queue the scan to start
        db.session.commit()
        tasks.scan.apply_async([scan.scan_uuid], countdown=3, queue='scan')
    # Handle stop
    if state == 'STOP':
        scans.update({"id": scan_id}, {"$set": {"state": "STOPPING", "queued": datetime.datetime.utcnow()}})
        tasks.scan_stop.apply_async([scan.scan_uuid], queue='state')
    return jsonify(success=True)

