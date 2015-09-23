﻿# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import Queue
import datetime
import json
import logging
import os
import signal
import socket
import subprocess
import threading
import time
import traceback
import uuid

from celery import Celery
from celery.app.control import Control
from celery.exceptions import TaskRevokedError
from celery.execute import send_task
from celery.signals import celeryd_after_setup
from celery.task.control import revoke
from celery.utils.log import get_task_logger
import requests
from twisted.internet import reactor
from twisted.internet.error import ProcessDone, ProcessTerminated, ProcessExitedAlready
from twisted.internet.protocol import ProcessProtocol

from minion.backend import ownership
from minion.backend.utils import backend_config, scan_config, scannable
from minion.backend.models import Plan, Scan, db, Session, Issue

cfg = backend_config()
celery = Celery('tasks', broker=cfg['celery']['broker'], backend=cfg['celery']['backend'])

# If the config does not mention mongo then we do not set it up. That is ok because
# that will only happen in plugin-workers that do not need direct mongodb access.

logger = get_task_logger(__name__)



@celery.task
def scan_start(scan_id, t):
    scan = Scan.get_scan(scan_id)
    old_state = scan.state
    scan.state = "STARTED"
    scan.started =  datetime.datetime.utcfromtimestamp(t)
    logger.debug("Starting scan [%s] [%s -> %s]" % (scan_id, old_state, scan.state))
    db.session.commit()


@celery.task
def run_scheduled_scan(target, plan):
    #1: First create a scan
    data = {
        'plan': plan,
        'configuration': {'target': target},
        'user': 'cron'
      }

    r = requests.post(cfg['api']['url'] + "/scans", 
        headers={'Content-Type':'application/json'},
        data=json.dumps(data));
    r.raise_for_status()
    scan_id = r.json()['scan']['id']


    
    logger.debug("Scheduled scan created - Target:" + target + " Plan:" + plan + " Request result: " + str(r.status_code))
    


    #2: Start the scan
    q = requests.put(cfg['api']['url'] + "/scans/" + scan_id + "/control",
        headers={'Content-Type':'text/plain'},
        data="START",
        params={"email":'cron'});

    q.raise_for_status()
    logger.debug("Scheduled scan STARTED - Target:" + target + " Plan:" + plan + "  result: " + str(q.status_code))
    
    return "Scan scheduled: " + scan_id + " r:" + str(r.status_code) + " q:"+ str(q.status_code)



@celery.task
def scan_finish(scan_id, state, t, failure=None):
    logger.debug("Attempting to finish scan for [%s] in state [%s]" % (scan_id, state))
    try:

        #
        # Find the scan we are asked to finish
        #
        scan = Scan.get_scan(scan_id)

        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Mark the scan as finished with the provided state
        #

        if failure:
            scan.state = state
            scan.finished =  datetime.datetime.utcfromtimestamp(t)
            scan.failure = failure
        else:
            scan.state = state
            scan.finished =  datetime.datetime.utcfromtimestamp(t)

        db.session.commit()

        #
        # Fire the callback
        #

        try:
            logger.debug("... Attempting to to invoke callback")
            config = json.loads(scan.configuration)

            callback = config.get('callback')
            if callback:
                r = requests.post(callback['url'], headers={"Content-Type": "application/json"},
                                  data=json.dumps({'event': 'scan-state', 'id': scan.scan_uuid, 'state': state}))
                r.raise_for_status()
        except Exception as e:
            logger.exception("(Ignored) failure while calling scan state callback for scan %s" % scan['id'])

        #
        # If there are remaining plugin sessions that are still in the CREATED state
        # then change those to CANCELLED because we wont be executing them anymore.
        #
        for s in scan.sessions:
            if s.state == 'CREATED':
                s.state = 'CANCELLED'
        db.session.commit()

    except Exception as e:

        logger.exception("Error while finishing scan. Trying to mark scan as FAILED.")

        try:
            scan = Scan.get_scan(scan_id)
            scan.state = "FAILED"
            scan.finished = datetime.datetime.utcnow()
            
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")


#pointer
@celery.task
def scan_stop(scan_id):

    logger.debug("This is scan_stop " + str(scan_id))

    try:

        #
        # Find the scan we are asked to stop
        #

        scan = Scan.get_scan(scan_id)
        if not scan:
            logger.error("Cannot find scan %s" % scan_id)
            return

        #
        # Set the scan to cancelled. Even though some plugins may still run.
        #
        logger.debug("Stopping scan %s [%s -> STOPPED]" % (scan.scan_uuid, scan.state))
        scan.state = "STOPPED"
        scan.started = datetime.datetime.utcnow()


        #
        # Set all QUEUED and STARTED sessions to STOPPED and revoke the sessions that have been queued
        #

        for session in scan.sessions:
            if session.state in ('QUEUED', 'STARTED'):
                session.state = "STOPPED"
                session.finished = datetime.datetime.utcnow()
                db.session.commit()
            if session.task:
                revoke(session.task, terminate=True, signal='SIGUSR1')

    except Exception as e:

        logger.exception("Error while processing task. Marking scan as FAILED.")

        try:
            if scan:
                scan = Scan.get_scan(scan_id)
                scan.state = "FAILED"
                scan.finished = datetime.datetime.utcnow()
                db.session.commit()
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

@celery.task
def session_queue(scan_id, session_id, t):
    logger.debug("Queuing session [%s] for scan [%s]" % (session_id, scan_id))
    scan = Scan.get_scan(scan_id)
    for session in scan.sessions:
        session.state = "QUEUED"
        scan.queued = datetime.datetime.utcfromtimestamp(t)
    db.session.commit()

@celery.task
def session_start(scan_id, session_id, t):
    scan = Scan.get_scan(scan_id)
    logger.debug("Starting session [%s] for scan [%s] [%s -> STARTED]" % (session_id, scan_id, scan.state))
    for session in scan.sessions:
        session.state = "STARTED"
        session.started = datetime.datetime.utcfromtimestamp(t)
    
    db.session.commit()
    

@celery.task
def session_set_task_id(scan_id, session_id, task_id):
    scan = Scan.get_scan(scan_id)
    logger.debug("Setting task id for session [%s]" % (session_id))
    for s in scan.sessions:
        if s.session_uuid == session_id:
            s.task = task_id
    db.session.commit()

@celery.task
def session_report_issue(scan_id, session_id, issue):
    logger.debug("Starting session [%s] for scan [%s]" % (session_id, scan_id))
    session = Session.get_session(session_id)

    i = Issue()
    i.code = issue["Code"]
    i.description = issue["Description"]

    i.further_info = json.dumps(issue["FurtherInfo"])
    i.urls = json.dumps(issue["URLs"])
    i.severity = issue["Severity"]
    i.summary = issue["Summary"]

    db.session.add(i)
    session.issues.append(i)
    db.session.commit()

@celery.task
def session_finish(scan_id, session_id, state, t, failure=None):
    #  params = [scan['id'], session['id'], msg['data']['state'], time.time(), msg['data']['failure']]
    logger.debug("Finishing session [%s] for scan [%s]" % (session_id, scan_id))
    s = Session.get_session(session_id)
    s.state = state
    s.finished = datetime.datetime.utcfromtimestamp(t)
    s.failure = failure
    db.session.commit()

# plugin_worker







plugin_runner_process = None


#
#
#

class Runner(ProcessProtocol):

    def __init__(self, plugin_class, configuration, session_id, callback):
        self._plugin_class = plugin_class
        self._configuration = configuration
        self._session_id = session_id
        self._callback = callback
        self._exit_status = None
        self._process = None
        self._buffer = ""

    # ProcessProtocol Methods

    def _parseLines(self, buffer):
        lines = buffer.split("\n")
        if len(lines) == 1:
            return ([], buffer)
        elif buffer.endswith("\n"):
            return (lines[0:-1],"")
        else:
            return (lines[0:-1],lines[-1])

    def outReceived(self, data):
        # Parse incoming data, taking incomplete lines into account
        buffer = self._buffer + data
        lines, self._buffer = self._parseLines(buffer)
        # Process all the complete lines that we received
        for line in lines:
            self._process_message(line)

    def errReceived(self, data):
        pass # TODO What to do with stderr?

    def processEnded(self, reason):
        if isinstance(reason.value, ProcessTerminated):
            self._exit_status = reason.value.status
        if isinstance(reason.value, ProcessDone):
            self._exit_status = reason.value.status
        self._process = None
        reactor.stop()

    # Runner

    def _process_message(self, message):
        # TODO Harden this by catching JSON parse errors and invalid messages
        m = json.loads(message)
        self._callback(m)

    def _locate_program(self, program_name):
        for path in os.getenv('PATH').split(os.pathsep):
            program_path = os.path.join(path, program_name)
            if os.path.isfile(program_path) and os.access(program_path, os.X_OK):
                return program_path

    def run(self):

        #
        # Setup the arguments
        #

        self._arguments = [ "minion-plugin-runner",
                           "-c", json.dumps(self._configuration),
                           "-p", self._plugin_class,
                           "-s", self._session_id ]

        #
        # Spawn a plugin-runner process
        #

        plugin_runner_path = self._locate_program("minion-plugin-runner")
        if plugin_runner_path is None:
            # TODO EMIT FAILURE
            return False

        self._process = reactor.spawnProcess(self, plugin_runner_path, self._arguments, env=None)

        #
        # Run the twisted reactor. It will be stopped either when the plugin-runner has
        # finished or when it has timed out.
        #

        reactor.run()

        return self._exit_status

    def terminate(self):
        if self._process is not None:
            try:
                self._process.signalProcess('KILL')
            except ProcessExitedAlready as e:
                pass
        if self._terminate_id is not None:
            if self._terminate_id.active():
                self._terminate_id.cancel()
            self._terminate_id = None

    def schedule_stop(self):

        #
        # Send the plugin runner a USR1 signal to tell it to stop. Also
        # start a timer to force kill the runner if it does not stop
        # on time.
        #

        self._process.signalProcess(signal.SIGUSR1)
        self._terminate_id = reactor.callLater(10, self.terminate)


def get_scan(api_url, scan_id):
    r = requests.get(api_url + "/scans/" + scan_id)
    r.raise_for_status()
    j = r.json()
    return j['scan']

def get_site_info(api_url, url):
    r = requests.get(api_url + '/sites', params={'url': url})
    r.raise_for_status()
    j = r.json()
    return j['sites'][0]

def set_finished(scan_id, state, failure=None):
    send_task("minion.backend.tasks.scan_finish",
              [scan_id, state, time.time(), failure],
              queue='state').get()

#
# run_plugin
#

def find_session(scan, session_id):
    for session in scan['sessions']:
        if session['id'] == session_id:
            return session

@celery.task
def run_plugin(scan_id, session_id):

    logger.debug("This is run_plugin " + str(scan_id) + " " + str(session_id))

    try:

        #
        # Find the scan for this plugin session. Bail out if the scan has been marked as STOPPED or if
        # the state is not STARTED.
        #
        logger.debug("Retrieving scan to run plugin [%s]" % scan_id)
        scan = get_scan(cfg['api']['url'], scan_id)
        if not scan:
            logger.error("Cannot load scan %s" % scan_id)
            return

        if scan['state'] in ('STOPPING', 'STOPPED'):
            return

        if scan['state'] != 'STARTED':
            logger.error("Scan %s has invalid state. Expected STARTED but got %s" % (scan_id, scan['state']))
            return

        #
        # Find the plugin session in the scan. Bail out if the session has been marked as STOPPED or if
        # the state is not QUEUED.
        #

        session = find_session(scan, session_id)
        db_session = Session.get_session(session_id)

        if not session:
            logger.error("Cannot find session %s/%s" % (scan_id, session_id))
            return

        if db_session.state != 'QUEUED':
            logger.error("Session %s/%s has invalid state. Expected QUEUED but got %s" % (scan_id, session_id, session['state']))
            return

        #
        # Move the session in the STARTED state
        #
        send_task("minion.backend.tasks.session_start",
                  [scan_id, session_id, time.time()],
                  queue='state').get()
        scan['state'] = 'STARTED'

        db_scan = Scan.get_scan(scan['id'])
        db_scan.state = 'STARTED'
        db.session.commit()
        finished = None

        #
        # This is an experiment to see if removing Twisted makes the celery workers more stable.
        #

        def enqueue_output(fd, queue):
            try:
                for line in iter(fd.readline, b''):
                    queue.put(line)
            except Exception as e:
                logger.exception("Error while reading a line from the plugin-runner")
            finally:
                fd.close()
                queue.put(None)

        def make_signal_handler(p):
            def signal_handler(signum, frame):
                p.send_signal(signal.SIGUSR1)
            return signal_handler

        arguments = [ "minion-plugin-runner",
                      "-c", json.dumps(session['configuration']),
                      "-p", session['plugin']['class'],
                      "-s", session_id ]

        p = subprocess.Popen(arguments, bufsize=1, stdout=subprocess.PIPE, close_fds=True)

        signal.signal(signal.SIGUSR1, make_signal_handler(p))

        q = Queue.Queue()
        t = threading.Thread(target=enqueue_output, args=(p.stdout, q))
        t.daemon = True
        t.start()

        while True:
            try:
                line = q.get(timeout=0.25)
                if line is None:
                    break

                line = line.strip()

                if finished is not None:
                    logger.error("Plugin emitted (ignored) message after finishing: " + line)
                    return

                msg = json.loads(line)

                # Issue: persist it
                if msg['msg'] == 'issue':
                    send_task("minion.backend.tasks.session_report_issue",
                              args=[scan_id, session_id, msg['data']],
                              queue='state').get()

                # Progress: update the progress
                if msg['msg'] == 'progress':
                    pass # TODO

                # Finish: update the session state, wait for the plugin runner to finish, return the state
                if msg['msg'] == 'finish':
                    logger.debug("MESSAGE : %s" % json.dumps(msg))
                    finished = msg['data']['state']
                    
                    if msg['data']['state'] in ('FINISHED', 'FAILED', 'STOPPED', 'TERMINATED', 'TIMEOUT', 'ABORTED'):
                        try:
                          params = [scan['id'], session['id'], msg['data']['state'], time.time(), msg['data'].get('failure')]
                        except Exception as e:
                            logger.debug("[Error] %s" % e)
                        send_task("minion.backend.tasks.session_finish", args = params, queue='state').get()

            except Queue.Empty:
                pass

        return_code = p.wait()

        signal.signal(signal.SIGUSR1, signal.SIG_DFL)

        if not finished:
            failure = { "hostname": socket.gethostname(),
                        "message": "The plugin did not finish correctly",
                        "exception": None }
            send_task("minion.backend.tasks.session_finish",
                      [scan['id'], session['id'], 'FAILED', time.time(), failure],
                      queue='state').get()

        return finished

    except Exception as e:

        #
        # Our exception strategy is simple: if anything was thrown above that we did not explicitly catch then
        # we assume there was a non recoverable error that made the plugin session fail. We mark it as such and
        # record the exception.
        #

        logger.exception("Error while running plugin session. Marking session FAILED.")

        try:
            failure = { "hostname": socket.gethostname(),
                        "message": str(e),
                        "exception": traceback.format_exc() }
            send_task("minion.backend.tasks.session_finish",
                      [scan_id, session_id, "FAILED", time.time(), failure],
                      queue='state').get()
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")

        return "FAILED"





# scan worker






def get_scan(api_url, scan_id):
    r = requests.get(api_url + "/scans/" + scan_id)
    r.raise_for_status()
    j = r.json()
    return j['scan']

def queue_for_session(session, cfg):
    queue = 'plugin'
    if 'plugin_worker_queues' in cfg:
        weight = session['plugin']['weight']
        if weight in ('heavy', 'light'):
            queue = cfg['plugin_worker_queues'][weight]
    return queue

@celery.task(ignore_result=True)
def scan(scan_id):
    logger.debug("Starting scan [%s] (scan:572)" % scan_id)
    try:

        #
        # See if the scan exists.
        #
        logger.debug("Retrieving scan for scan() [%s]" % scan_id)
        scan = get_scan(cfg['api']['url'], scan_id)
        if not scan:
            logger.error("Cannot load scan %s" % scan_id)
            return

        #
        # Is the scan in the right state to be started?
        #

        if scan['state'] != 'QUEUED':
            logger.error("Scan %s has invalid state. Expected QUEUED but got %s" % (scan_id, scan['state']))
            return

        #
        # Move the scan to the STARTED state
        #
        db_scan = Scan.get_scan(scan['id'])
        db_scan.state = 'STARTED'
        scan['state'] = 'STARTED'
        db.session.commit()
        
        send_task("minion.backend.tasks.scan_start", [scan_id, time.time()], queue='state').get()

        #
        # Check this site against the access control lists
        #

        if not scannable(scan['configuration']['target'],
                         scan_config().get('whitelist', []),
                         scan_config().get('blacklist', [])):
            failure = {"hostname": socket.gethostname(),
                       "reason": "target-blacklisted",
                       "message": "The target cannot be scanned by Minion because its IP address or hostname has been blacklisted."}
            return set_finished(scan_id, 'ABORTED', failure=failure)

        #
        # Verify ownership prior to running scan
        #

        target = scan['configuration']['target']
        site = get_site_info(cfg['api']['url'], target)
        if not site:
            return set_finished(scan_id, 'ABORTED')

        if site.get('verification') and site['verification']['enabled']:
            verified = ownership.verify(target, site['verification']['value'])
            if not verified:
                failure = {"hostname": socket.gethostname(),
                           "reason": "target-ownership-verification-failed",
                           "message": "The target cannot be scanned because the ownership verification failed."}
                return set_finished(scan_id, 'ABORTED', failure=failure)

        #
        # Run each plugin session
        #

        for session in scan['sessions']:

            #
            # Mark the session as QUEUED
            #

            db_session = Session.get_session(session['id'])
            db_session.state = 'QUEUED'
            session['state'] = 'QUEUED'
            db.session.commit()
            #scans.update({"id": scan['id'], "sessions.id": session['id']}, {"$set": {"sessions.$.state": "QUEUED", "sessions.$.queued": datetime.datetime.utcnow()}})
            send_task("minion.backend.tasks.session_queue",
                      [scan['id'], session['id'], time.time()],
                      queue='state').get()

            #
            # Execute the plugin. The plugin worker will set the session state and issues.
            #
            db.session.commit()
            

            queue = queue_for_session(session, cfg)
            result = send_task("minion.backend.tasks.run_plugin",
                               [scan_id, session['id']],
                               queue=queue)

            #scans.update({"id": scan_id, "sessions.id": session['id']}, {"$set": {"sessions.$._task": result.id}})
            send_task("minion.backend.tasks.session_set_task_id",
                      [scan_id, session['id'], result.id],
                      queue='state').get()

            try:
                plugin_result = result.get()
            except TaskRevokedError as e:
                plugin_result = "STOPPED"

            db_session = Session.get_session(session['id'])
            db_session.state = plugin_result
            session['state'] = plugin_result

            db.session.commit()
            #
            # If the user stopped the workflow or if the plugin aborted then stop the whole scan
            #

            if plugin_result in ('ABORTED', 'STOPPED'):
                # Mark the scan as failed
                #scans.update({"id": scan_id}, {"$set": {"state": plugin_result, "finished": datetime.datetime.utcnow()}})
                send_task("minion.backend.tasks.scan_finish",
                          [scan_id, plugin_result, time.time()],
                          queue='state').get()
                # Mark all remaining sessions as cancelled
                for s in scan['sessions']:
                    if s['state'] == 'CREATED':
                        s['state'] = 'CANCELLED'
                        dbs =  Session.get_session(s['id'])
                        s.state = 'CANCELLED'
                        db.session.commit()
                        #scans.update({"id": scan['id'], "sessions.id": s['id']}, {"$set": {"sessions.$.state": "CANCELLED", "sessions.$.finished": datetime.datetime.utcnow()}})
                        send_task("minion.backend.tasks.session_finish",
                                  [scan['id'], s['id'], "CANCELLED", time.time()],
                                  queue='state').get()
                # We are done with this scan
                return

        #
        # Move the scan to the FINISHED state
        #

        scan['state'] = 'FINISHED'
        db_scan = Scan.get_scan(scan['id'])
        db_scan.state = 'FINISHED'
        db.session.commit()

        #
        # If one of the plugin has failed then marked the scan as failed
        #
        for session in scan['sessions']:
            if session['state'] == 'FAILED':
                db_scan = Scan.get_scan(scan['id'])
                db_scan.state = 'FAILED'
                db.session.commit()
                scan['state'] = 'FAILED'

        #scans.update({"id": scan_id}, {"$set": {"state": "FINISHED", "finished": datetime.datetime.utcnow()}})
        send_task("minion.backend.tasks.scan_finish",
                  [scan_id, scan['state'], time.time()],
                  queue='state').get()

    except Exception as e:

        #
        # Our exception strategy is simple: if anything was thrown above that we did not explicitly catch then
        # we assume there was a non recoverable error that made the scan fail. We mark it as such and
        # record the exception.
        #

        logger.exception("Error while running scan. Marking scan FAILED.")

        try:
            failure = { "hostname": socket.gethostname(),
                        "reason": "backend-exception",
                        "message": str(e),
                        "exception": traceback.format_exc() }
            send_task("minion.backend.tasks.scan_finish",
                      [scan_id, "FAILED", time.time(), failure],
                      queue='state').get()
        except Exception as e:
            logger.exception("Error when marking scan as FAILED")
