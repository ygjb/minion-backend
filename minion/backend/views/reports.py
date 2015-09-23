#!/usr/bin/env python

import calendar
import datetime
import importlib
import json
import uuid

from flask import jsonify, request

import minion.backend.utils as backend_utils
import minion.backend.tasks as tasks
from minion.backend.app import app
from minion.backend.views.base import api_guard
from minion.backend.models import db, User, Group, Site, ScanSchedule, Scan
from minion.backend.views.scans import sanitize_scan, summarize_scan

# API Methods to return reports

#
# Returns a scan history report, which is simply a list of all
# scans that have been recently done.
#
# If the user is specified then only scans are returned that
# the user can see.

@app.route('/reports/history', methods=['GET'])
@api_guard
def get_reports_history():
    history = []
    user_email = request.args.get('user')
    scans = []
    if user_email is not None:
        user = User.get_user(user_email)
        if user is None:
            return jsonify(success=False, reason='no-such-user')

        
        # Get Sites
        for site in user.sites():
            for scan in Site.get_site_by_url(site).scans:
                scans.append(scan)

        scans.sort(key=lambda x : x.created, reverse = True)
        # Get Scans for Sites
    else:
        for site in Site.query.all():
            for scan in site.scans:
                scans.append(scan)

    for s in scans[:100]:
            history.append(summarize_scan(s))
    return jsonify(success=True, report=history)

#
# Returns a status report that lists each site and attached plans
# together with the results from the last scan done. It also returns
# the crontab schedule if the scan has been scheduled.
#
# If the user is specified then the report will only include data
# that the user can see.
# Accept a filter query: groups?=<group_name>&user?=<email_address>
#
#  { 'report':
#       [{ 'plan': 'basic',
#          'scan': [...],
#          'target': 'http://www.mozilla.com',
#          'crontab': {
#             'minute'        : '*',
#             'hour'          : '*', 
#             'day_of_week'   : '*',
#             'day_of_month'  : '*',
#             'month_of_year' : '*'
#           },
#           'scheduleEnabled': True
#       }],
#    'success': True }

# XXX this whole thing just shows how fucky the data model is.  Sites / Scans need to be strongly linked, and we shouldn't have to do voodo to filter scans by name/site/plan/etc.
@app.route('/reports/status', methods=['GET'])
@api_guard
def get_reports_sites():
    result = []
    group_name = request.args.get('group_name')
    user_email = request.args.get('user')

    if user_email is not None:
        # User specified, so return recent scans for each site/plan that the user can see
        user = User.get_user(user_email)
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        if group_name:
            group = Group.get_group(group_name)
            if group is None:
                return jsonify(success=False, reason='no-such-group')

            site_list = map(lambda x: x.url, group.sites)
        else:
            site_list = user.sites()
        for site_url in sorted(site_list):
            site = Site.get_site_by_url(site_url)
            if site is not None:
                for plan in site.plans:
                    plan_name = plan.name
                    schedule = ScanSchedule.get_schedule(site.site_uuid, plan.plan_uuid)

                    crontab = None
                    scheduleEnabled = False
                    if schedule is not None:
                        crontab = schedule['crontab']
                        scheduleEnabled = schedule['enabled']

                    scans = []
                    for scan in site.scans:
                        if scan.plan is not None:
                            p = json.loads(scan.plan)
                            if p['name'] == plan_name:
                                scans.append(scan)                    

                    scan_for_site = []
                    for scan in scans:
                        config = json.loads(scan.configuration)
                        
                        if config.get('target', None) == site_url:
                            scan_for_site.append(scan)


                    o = list(sorted(scan_for_site, cmp= lambda x, y: cmp(x.created, y, created)))
                    if len(o):
                     l = [o[0]]
                    else:
                     l = []         
                    
                    if len(l) == 1:
                        scan = summarize_scan(l[0])
                        s = {v: scan.get(v) for v in ('id', 'created', 'state', 'issues')}
                        result.append({'target': site_url, 'plan': plan_name, 'scan': scan, 'crontab': crontab, 'scheduleEnabled': scheduleEnabled})
                    else:
                        result.append({'target': site_url, 'plan': plan_name, 'scan': None, 'crontab': crontab, 'scheduleEnabled': scheduleEnabled})
    return jsonify(success=True, report=result)

#
# Returns a status report that lists each site and attached plans
# together with the results from the last scan done.
#
# Accept a filter query: groups?=<group_name>&user?=<email_address>
# If the user is specified then the report will only include data
# that the user can see.
#  { 'report':
#       [{ 'issues': [..],
#          'target': 'http://mozilla.com
#       }],
#    'success': True }

@app.route('/reports/issues', methods=['GET'])
@api_guard
def get_reports_issues():
    result = []
    group_name = request.args.get('group_name')
    user_email = request.args.get('user')
    if user_email is not None:
        # User specified, so return recent scans for each site/plan that the user can see
        user = User.get_user(user_email)
        if user is None:
            return jsonify(success=False, reason='no-such-user')
        site_list = []
        if group_name:
            # get list of sites for group

            site_list = _find_sites_for_user_by_group_name(user_email, group_name)
            
            g = Group.get_group(group_name)
            if g:
                for site in g.sites:
                    site_list.append(site.url)


        else:
            site_list = User.get_user(user_email).sites()


        for site_url in sorted(site_list):
            r = {'target': site_url, 'issues': []}
            site = Site.get_site_by_url(site_url)
            if site is not None:
                scan_list = []
                for scan in site.scans:
                    scan_list.append(scan)

                if len(scan_list) > 0:
                    scan_list.sort(key=lambda x : x.created, reverse=True)
                    s = scan_list[0]
                    for session in s.sessions:
                            for issue in session.issues:
                                r['issues'].append({'severity': issue.severity,
                                                    'summary': issue.summary,
                                                    'scan': { 'id': s.scan_uuid},
                                                    'id': issue.issue_uuid})    

                
            result.append(r)
    return jsonify(success=True, report=result)
