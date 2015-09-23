import uuid
import calendar
import datetime
import functools
import importlib
import json
import pkgutil
import operator
import logging

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, backref

from minion.backend.utils import backend_config
from minion.plugins.base import AbstractPlugin
import inspect

cfg = backend_config()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/minion/minion.db'
db = SQLAlchemy(app)


# XXX - uh, I need to ensure that UUIDs are unique by table.
def generate_uuid():
  return str(uuid.uuid4())



class User(db.Model):
 
 user_uuid = db.Column(db.String(36), primary_key = True)
  
 name = db.Column(db.String(127), unique=True)
 email = db.Column(db.String(254), unique=True)

 created = db.Column(db.DateTime)
 last_login = db.Column(db.DateTime)
 active = db.Column(db.DateTime)
 status = db.Column(db.String(127))
 role = db.Column(db.String(127))
 api_key = db.Column(db.String(127))
 auth_data = db.Column(db.Text)
 

 def __init__(self, username, email):
        self.name = username
        self.email = email
        self.created = datetime.datetime.utcnow()
        self.role = 'user'
        self.last_login = None
        self.api_key = generate_uuid()
        self.user_uuid = generate_uuid()
        self.status = "active"


 def __repr__(self):
        return '<User %r>' % self.name

 def sites(self):
  sitez = []
  for group in self.groups:
   for site in group.sites:
    if site.url not in sitez:
     sitez.append(site.url)
  return sitez

 def dict(self):
  
  created = last_login = None
  if self.created:
        created = calendar.timegm(self.created.utctimetuple())
  if self.last_login:
        last_login = calendar.timegm(self.last_login.utctimetuple())
  result = { 
  'id' : self.user_uuid, 
  'last_login' : last_login, 
  'name' : self.name, 
  'role' : self.role, 
  'api_key' : self.api_key,
  'created' : created,
  'email' : self.email,
  'groups' : map(lambda x : x.name, self.groups),
  'sites' : self.sites(),
  'status' : self.status}
  return result 

 @staticmethod
 def get_user(email):
    try:
        return User.query.filter_by(email = email).one()
    except:
        return None


group_site_associations = db.Table("group_site_associations", db.Column('group', db.String(36), db.ForeignKey('group.group_uuid')),
db.Column('site', db.String(36), db.ForeignKey('site.site_uuid')))


user_group_associations = db.Table("user_group_associations", db.Column('user', db.String(36), db.ForeignKey('user.user_uuid')),
db.Column('group', db.String(36), db.ForeignKey('group.group_uuid')))

class Group(db.Model):
 group_uuid = db.Column(db.String(36), primary_key = True)
 name = db.Column(db.String(127), unique=True)
 
 owner = db.Column(db.String(36), db.ForeignKey('user.user_uuid'))
 admin_group = db.Column(db.String(36), db.ForeignKey('group.group_uuid'))
 description = db.Column(db.Text)
 created = db.Column(db.DateTime)

 users = relationship("User", backref=backref('groups'), secondary=user_group_associations)
 sites = relationship("Site", backref=backref('groups'), secondary=group_site_associations)



 def __init__(self, name, email, admin_group):
        self.name = name
        self.owner = User.query.filter(User.email == email).first().user_uuid
        self.group_uuid = generate_uuid()
        if admin_group == None:
            self.admin_group = self.group_uuid
        else:
            self.admin_group = admin_group.uuid
        self.created = datetime.datetime.utcnow()
        

 def __repr__(self):
        return '<Group %r>' % self.name

 @staticmethod
 def get_group(name):
        try:
            return Group.query.filter_by(name = name).one()
        except:
            return None

 def dict(self):
  created =  None
  if self.created:
        created = calendar.timegm(self.created.utctimetuple())
  result = { 
  'name' : self.name, 
  'created' : created,
  'owner' : self.owner,
  'sites' : map(lambda x : x.url, self.sites),
  'users' : map(lambda x : x.email, self.users)}
  return result 




class Site(db.Model):
 site_uuid = db.Column(db.String(36), primary_key = True)
 url = db.Column(db.String)
 group = db.Column(db.String(36), db.ForeignKey('group.group_uuid'))
 created = db.Column(db.DateTime)

 scans = relationship('Scan', backref="site")
 def __init__(self, url):
        self.url = url
        self.created = datetime.datetime.utcnow()
        self.site_uuid = generate_uuid()


 @staticmethod
 def get_site_by_url(url):
        try:
                return Site.query.filter_by(url = url).one()
        except:
                return None

 @staticmethod
 def get_site(uuid):
    try:
          return Site.query.filter_by(site_uuid = uuid).one()
    except:
          return None


 def dict(self):
  created =  None
  if self.created:
   created = calendar.timegm(self.created.utctimetuple())
   result = { 
   'id' : self.site_uuid, 
   'created' : created,
   'url' : self.url,
   'groups' : map(lambda x : x.name, self.groups),
   'plans': map(lambda x : x.name, self.plans)}
  return result 


class Invite(db.Model):
 
 invite_uuid = db.Column(db.String(36), primary_key = True)
 recipient = db.Column(db.String)
 recipient_name = db.Column(db.String)
 sender = db.Column(db.String(36), db.ForeignKey('user.user_uuid'))
 sender_name = db.Column(db.String)

 sent_on = db.Column(db.DateTime)
 accepted_on = db.Column(db.DateTime)
 status = db.Column(db.String)
 expire_on = db.Column(db.DateTime)
 max_time_allowed = db.Column(db.DateTime)

 notify_when = db.Column(db.String)


 def __init__(self, recipient, recipient_name, sender, expire_on, max_time_allowed):
  user = User.get_user(sender)
  if user is None:
        raise ValueError('The specified user does not exist')
 
  self.invite_uuid = generate_uuid()
  self.recipient = recipient
  self.recipient_name = recipient_name
  self.sender = user.email
  self.sender_name = user.username

  self.sent_on = None
  self.accepted_on = None
  self.status = "pending"
  self.expire_on = expire_on
  self.max_time_allowed = max_time_allowed

 @staticmethod
 def get_invite(id):
    try:
      return Invite.query.filter_by(invite_uuid = id).one()
    except:
      return None


 
site_plan_associations = db.Table("site_plan_associations", db.Column('site', db.String(36), db.ForeignKey('site.site_uuid')),
db.Column('plan', db.String(36), db.ForeignKey('plan.plan_uuid')))

class Plan(db.Model):
 
 plan_uuid = db.Column(db.String(36), primary_key = True)
 created = db.Column(db.DateTime)
 name = db.Column(db.String(127))
 description = db.Column(db.Text)
 sites = relationship("Site", backref=backref('plans'), secondary = site_plan_associations)
 def __init__(self):
  self.created = datetime.datetime.utcnow()
  self.plan_uuid = generate_uuid()

 def dict(self):
  created =  None
  if self.created:
    created = calendar.timegm(self.created.utctimetuple())
  result = { 
   'id' : self.plan_uuid, 
   'created' : created,
   'name' : self.name,
   'description' : self.description,
   'workflow' : map(lambda x:x.dict(), self.workflows)
  }
  return result
 @staticmethod
 def get_plan(name):
    try:
      return Plan.query.filter_by(name = name).one()
    except:
      return None

 
plan_workflow_associations = db.Table("plan_workflow_associations", db.Column('plan', db.String(36), db.ForeignKey('plan.plan_uuid')),
db.Column('worklow', db.String(36), db.ForeignKey('workflow.workflow_uuid')))


class Workflow(db.Model):
 
 workflow_uuid = db.Column(db.String(36), primary_key = True)
 
 plugin_name = db.Column(db.String)
 description = db.Column(db.String(127))
 created = db.Column(db.DateTime)
 

 configuration = db.Column(db.Text)

 plan = relationship("Plan", backref=backref('workflows'), secondary = plan_workflow_associations)
 def __init__(self):
  self.created = datetime.datetime.utcnow()
  self.workflow_uuid = generate_uuid()

 def dict(self):
  created =  None
  if self.created:
   created = calendar.timegm(self.created.utctimetuple())
  config = []
  if self.configuration:
    config = json.loads(self.configuration)

  result = { 
   'plugin_name' : self.plugin_name, 
   'created' : created,
   'description' : self.description,
   'configuration' : config
  }
  return result 


class Scan(db.Model):
 
 scan_uuid = db.Column(db.String(36), primary_key = True)

 created = db.Column(db.DateTime)
 finished = db.Column(db.DateTime)
 queued = db.Column(db.DateTime)
 started = db.Column(db.DateTime)
 
 plan = db.Column(db.Text) 
 meta = db.Column(db.Text)
 configuration = db.Column(db.Text)

 state = db.Column(db.String(127))


 site_id = db.Column(db.String(36), db.ForeignKey('site.site_uuid'))
 sessions = relationship('Session', backref='scans')

 #failure
 failure = db.Column(db.Text)

 def __init__(self):
  self.created = datetime.datetime.utcnow()
  self.scan_uuid = generate_uuid()
  self.created = datetime.datetime.utcnow()
  self.queued = None
  self.started = None
  self.finished = None
  self.state = "CREATED"

 @staticmethod
 def get_scan(uuid):
    try:
        return Scan.query.filter_by(scan_uuid = uuid).one()
    except:
        return None




class Session(db.Model):
 
 session_uuid = db.Column(db.String(36), primary_key = True)
 task = db.Column(db.String(127))

 created = db.Column(db.DateTime)
 finished = db.Column(db.DateTime)
 queued = db.Column(db.DateTime)
 started =  db.Column(db.DateTime)



 plan = db.Column(db.Text) 
 meta = db.Column(db.Text)
 state = db.Column(db.String(127))
 progress = db.Column(db.String(127))

 plugin = db.Column(db.Text)

 configuration = db.Column(db.Text)

 scan_id = db.Column(db.String(36), db.ForeignKey('scan.scan_uuid'))
 issues = relationship('Issue', backref='session')
 artifacts = relationship('Artifact', backref='session')

 @staticmethod
 def get_session(uuid):
    try:
        return Session.query.filter_by(session_uuid = uuid).one()
    except:
        return None

 def __init__(self):
  self.created = datetime.datetime.utcnow()
  self.finished = None
  self.queued = None
  self.progress = None
  self.session_uuid = generate_uuid()
  self.state = "CREATED"
  self.plugin = None

 def dict(self, clean=False):
   plan = []
   configuration = []
   meta = []
   if self.plan:
    plan = json.loads(self.plan)
   if self.meta:
    meta = json.loads(self.meta)
   if self.configuration:
    configuration = json.loads(self.configuration)
   result = {
    'id' : self.session_uuid,
    'task' : self.task,
    'state' : self.state,
    'plan' : plan, 
    'meta' : meta,
    'progress' : self.progress,
    'plugin' : json.loads(self.plugin),
    'configuration' : configuration,

    'issues' : map( lambda x : x.dict(), self.issues),
    'artifacts' : map( lambda x : x.dict(), self.artifacts)
   }
   if self.created:
    result['created'] = calendar.timegm(self.created.utctimetuple())
   if self.finished:
    result['finished'] = calendar.timegm(self.finished.utctimetuple())
   if self.queued:
    result['queued'] = calendar.timegm(self.queued.utctimetuple())
   if self.started:
    result['started'] = calendar.timegm(self.created.utctimetuple())
   return result





class Issue(db.Model):
 
 issue_uuid = db.Column(db.String(36), primary_key = True)

 session_id = db.Column(db.String(36), db.ForeignKey('session.session_uuid'))

 severity = db.Column(db.String)


 code = db.Column(db.String(127))
 summary = db.Column(db.Text())
 description = db.Column(db.Text())
 further_info = db.Column(db.Text())
 urls = db.Column(db.Text())

 def __init__(self):
  self.created = datetime.datetime.utcnow()
  self.issue_uuid = generate_uuid()
  self.further_info = []
  self.urls = []
  self.description = None
  self.summary = None
  self.code = None
  self.severity = None
 
 def dict(self):
  result = {
   "Code" : self.code,
   "Description" : self.description,
   "Summary" : self.summary,
   "Id" : self.issue_uuid,
   "Severity" : self.severity,
   "FurtherInfo" : json.loads(self.further_info),
   "Urls" : json.loads(self.urls)
  }
  return result


class Artifact(db.Model):
 
 artifact_uuid = db.Column(db.String(36), primary_key = True)
 session_id = db.Column(db.String(36), db.ForeignKey('session.session_uuid'))

 def __init__(self):
  self.created = datetime.datetime.utcnow()
  self.artifact_uuid = generate_uuid()


















class ScanSchedule(db.Model):
 
 scanschedule_uuid = db.Column(db.String(36), primary_key = True)

 #punt.  This whole feature needs rewriting.

 site = db.Column(db.String(36), db.ForeignKey('site.site_uuid'))
 plan = db.Column(db.String(36), db.ForeignKey('plan.plan_uuid'))

 # just store the data object as a JSON object, serialize/deserialize as need be.
 data = db.Column(db.Text)

 def __init__(self):
  self.scanschedule_uuid = generate_uuid()


 @staticmethod
 def get_schedule(site, target):
  try:
    return ScanSchedule.query.filter(and_(ScanSchedule.site == site, ScanSchedule.target == target)).one()
  except:
    return None

class SiteCredential(db.Model):
 
 sitecredential_uuid = db.Column(db.String(36), primary_key = True)
 
 username = db.Column(db.String(127))
 password = db.Column(db.Text)
 emailaddress = db.Column(db.Text)
 script = db.Column(db.Text)
 url = db.Column(db.Text)

 username_path = db.Column(db.Text)
 password_path = db.Column(db.Text)
 method = db.Column(db.String(127))
 cookies = db.Column(db.Text)

 before_login_path = db.Column(db.Text)
 after_login_path = db.Column(db.Text)
 button_path = db.Column(db.Text)

 site_id = db.Column(db.String(36), db.ForeignKey('site.site_uuid'))
 plan_id = db.Column(db.String(36), db.ForeignKey('plan.plan_uuid'))

 def __init__(self, site_id, plan_id):
  self.sitecredential_uuid = generate_uuid()
  self.site_id = site_id
  self.plan_id = plan_id

 def dict(self, showPassword = False):
  password = ""
  if showPassword:
   password = self.password
  result = {
    "authData": {
    "username": self.username,
    "before_login_element_xpath": self.before_login_path,
    "login_script":self.script,
    "login_button_xpath": self.button_path,
    "url": self.url,
    "username_field_xpath": self.username_path,
    "method": self.method,
    "password_field_xpath": self.password_path,
    "expected_cookies": self.cookies,
    "after_login_element_xpath": self.after_login_path,
    "password": password,
    "email": self.emailaddress,
    },
    "site": Site.query.filter(site.site_uuid == self.site_id).one().url ,
    "plan": Plan.query.filter(plan.plan_uuid == self.plan_id).one().name
    }
  return result

 @staticmethod
 def get_credential(site, plan):
  try:
    return SiteCredential.query.filter(and_(SiteCredential.site_id == site, SiteCredential.plan_id == plan)).one()
  except:
    return None








# PLugin is here because it should behave like a database backed object.
# XX - Rewrite this functionality to store plugin data in the database
# XX - enable reloads at runtime so plugins can be installed and then discovered

class Plugin():
 
 
 plugins = { }

 @staticmethod
 def load_plugin():

    """ Load plugins if they are subclass of AbstractPlugin and
    are not known base subclasses such as BlockingPlugin. """

    DEFAULT_BASE_CLASSES = ('AbstractPlugin', 'BlockingPlugin', 'ExternalProcessPlugin')
    candidates = {}
    base_package = importlib.import_module('minion.plugins')
    prefix = base_package.__name__ + "."
    for importer, package, ispkg in pkgutil.iter_modules(base_package.__path__, prefix):
        module = __import__(package, fromlist=['plugins'])
        for name in dir(module):
            obj = getattr(module, name)
            if inspect.isclass(obj) and issubclass(obj, AbstractPlugin) and name not in DEFAULT_BASE_CLASSES:
                app.logger.info("Found %s" % str(obj))
                plugin_name = module.__name__ + '.' + obj.__name__
                candidates[plugin_name] = obj

    for plugin_name, plugin_obj in candidates.iteritems():
        try:
            Plugin._register_plugin(plugin_name, plugin_obj)
        except ImportError as e:
            app.logger.error("Unable to import %s" % plugin_name)
            pass

 @staticmethod
 def _register_plugin(plugin_name, plugin_class):
    Plugin.plugins[plugin_name] = {
        'clazz': plugin_class,
        'descriptor': {
            'class': plugin_name,
            'name': plugin_class.name(),
            'version': plugin_class.version(),
            'weight': plugin_class.weight()
        }
    }



