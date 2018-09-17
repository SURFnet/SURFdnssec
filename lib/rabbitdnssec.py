# rabbitdnssec.py -- DNSSEC management through a RabbitMQ cluster
#
# These routines can be used somewhat generally within a cluster of
# DNSSEC signers as we are using at SURFnet.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import socket
import time
import os.path
import importlib

import ssl
import json
import syslog
import atexit
import configparser

import pika
import pika.spec
import pika.credentials


# Setup configuration, such as settings and application name
#
homedir = os.path.expanduser ('~')
appdir = homedir + '/ods-amqp'
appname = os.path.basename (sys.argv [0])
appcfg = configparser.ConfigParser ()
appcfg.read ([appdir + '/config', '/etc/opendnssec/ods-amqp.config'])

# Recreate the prefix from sys.argv [0] and add to to $PATH
#
prefix = os.path.dirname (sys.argv [0])
os.environ ['PATH'] = prefix + ':' + os.environ.get ('PATH')

# Open syslog, using standard settings
#

def cleanup_syslog ():
	syslog.syslog (syslog.LOG_INFO, 'Program exiting')
	syslog.closelog ()

syslog.openlog (appname,
		(syslog.LOG_PERROR if sys.stderr.isatty () else 0) |
			syslog.LOG_PID,
		syslog.LOG_USER)

syslog.syslog (syslog.LOG_INFO, 'Program starting')

atexit.register (cleanup_syslog)

# Setup the RabbitMQ client
#
this_machine	= socket.gethostname ().split ('.') [0]
this_port	= int (appcfg ['rabbitmq'] ['port'])
vhost		=      appcfg ['rabbitmq'] ['vhost']
signer_cluster	=      appcfg ['rabbitmq'] ['signer_cluster']
signer_machines	=      appcfg ['rabbitmq'] ['signer_machines'].split ()
backup_machines =      appcfg ['rabbitmq'] ['backup_machines'].split ()
plugindir       =      appcfg ['rabbitmq'] ['plugindir']
ca_certs	=      appcfg ['rabbitmq'] ['ca_certs']
backend         =      appcfg ['rabbitmq'] ['backend']
#
assert ((this_machine in signer_machines) or (this_machine in backup_machines))
assert (len (signer_machines) >= 2)

# Setup for TLS
#
wrap_tls = True
conf_tls = {
	'ssl_version': ssl.PROTOCOL_TLSv1_2,
	'ca_certs':    ca_certs,
	'certfile':    appdir + '/ssl/certs/' + this_machine + '.pem',
	'keyfile':     appdir + '/ssl/private/'  + this_machine + '.pem',
	'server_side': False,
}

# Setup PKCS #11
#
pkcs11_libfile		= appcfg ['pkcs11'] ['libfile']
pkcs11_token_label	= appcfg ['pkcs11'] ['token_label']
pkcs11_pinfile_path	= appcfg ['pkcs11'] ['pinfile']
pkcs11_curve_name	= appcfg ['pkcs11'] ['curve_name']

# Send messages at various levels to syslog
#
def log_debug (msg, *args):
	for a in args:
		msg = msg + ' ' + unicode (a)
	syslog.syslog (syslog.LOG_DEBUG, msg)

def log_info (msg, *args):
	for a in args:
		msg = msg + ' ' + unicode (a)
	# msg = msg % tuple (map (str, args))
	syslog.syslog (syslog.LOG_INFO, msg)

def log_notice (msg, *args):
	for a in args:
		msg = msg + ' ' + unicode (a)
	# msg = msg % tuple (map (str, args))
	syslog.syslog (syslog.LOG_NOTICE, msg)

def log_warning (msg, *args):
	for a in args:
		msg = msg + ' ' + unicode (a)
	# msg = msg % tuple (map (str, args))
	syslog.syslog (syslog.LOG_WARNING, msg)

def log_error (msg, *args):
	for a in args:
		msg = msg + ' ' + unicode (a)
	# msg = msg % tuple (map (str, args))
	syslog.syslog (syslog.LOG_ERR, msg)

def log_critical (msg, *args):
	for a in args:
		msg = msg + ' ' + unicode (a)
	# msg = msg % tuple (map (str, args))
	syslog.syslog (syslog.LOG_CRIT, msg)

# Return the name of a queue on the current machine (prefix by hostname)
#
def my_queue (queue):
	return this_machine + '_' + queue

# Return the name of an exchange on the current machine (prefix by hostname)
#
def my_exchange (exchange='signer'):
	return this_machine + '_' + exchange

# Return configuration dict for the current app from config section [APPNAME]
# (Use ovr_appname to override the application name to something else)
#
def my_config (ovr_appname=None):
	global appcfg, appname
	assert (ovr_appname != 'accounts')
	if ovr_appname is None:
		ovr_appname = appname
	return appcfg [ovr_appname]

# Return the backend module name used for signing DNS zone data.
#
def my_backend ():
	return backend

# Return the plugin directory for this program.
#
def my_plugindir (ovr_appname=None):
	return plugindir + '/' + (ovr_appname or appname)

# Return the backend module used for signing DNS zone data.
# By default, a possible loading location is the plugin directory's
# subdirectory named by sys.argv [0], but ovr_appname can be used to
# override this default name for the application subdirectory under
# the plugin directory.
#
def my_backendmod (modname_prefix, modname_postfix='', ovr_appname=None):
	sys.path.append (my_plugindir (ovr_appname=ovr_appname))
	backendmod = importlib.import_module (
			modname_prefix + backend + modname_postfix )
	sys.path.pop ()
	return backendmod

# Retrieve a PlainCredentials object based on the current appname.
# Overrides exist for appname and username.
#
def my_credentials (ovr_appname=None, ovr_username=None):
	global appcfg, appname
	if ovr_username is None:
		username = appcfg [ovr_appname or appname] ['username']
	else:
		username = ovr_username
	password = appcfg ['accounts'] [username]
	return pika.PlainCredentials (username, password)

# Retrieve a ConnectionParameters objcet.  This is based on settings
# in the [rabbitmq] configuration section, which applies to all appnames
# under this UNIX account, except for the credentials which can be
# supplied here as a parameter, and may well be derived with
# my_credentials().
# 
def my_connectionparameters (my_creds, host=this_machine, port=this_port, **params):
	return pika.ConnectionParameters (
			host,
			port,
			virtual_host=vhost,
			ssl=wrap_tls,
			ssl_options=conf_tls,
			credentials=my_creds,
			**params)

# Construct a BasicProperties object, based on standard available
# information and optional headers.  There are options for overriding
# the username.
#
def my_basicproperties (headers=None, ovr_appname=None, ovr_username=None):
	return pika.spec.BasicProperties (
			timestamp=time.time (),
			user_id=(ovr_username or appcfg [
					ovr_appname or appname] ['username']),
			cluster_id=signer_cluster,
			headers=headers)

def pkcs11_pin ():
	"""Load the PKCS #11 PIN from the OpenDNSSEC configuration.
	"""
	return open (pkcs11_pinfile_path).read ().strip ()

def pkcs11_pinfile ():
	"""Return the PKCS #11 PIN file from the OpenDNSSEC configuration.
	"""
	return pkcs11_pinfile_path

class MessageCollector (object):

	"""MessageCollector synchronously loads at least one message,
	   but more when they are immediately available.  This helps
	   to speed up operations when work accumulates and batch-mode
	   operation is possible.  At the same time, it does not slow
	   down operations when messages drip in one at a time.

	   This is probably best combined with transactions, as in

		chan.tx_select ()
		clx = MessageCollector (chan)
		clx.collect ()
		...
		for m in clx.messages ():
			...inner.loop...
		...
		if ...we are happy...:
			clx.ack ()
		else:
			clx.nack ()
		chan.tx_commit ()
	"""

	def __init__ (self, chan, queue=None):
		self.chan = chan
		self.queue = queue
		self.msgtags = []
		self.msglist = []
		self.gotempty = False

	def messages (self):
		"""Return the list of messages collected.
		"""
		return self.msglist

	def count (self):
		"""Return the number of messages collected.
		"""
		return len (self.msglist)

	def ack (self):
		"""Send a basic_ack() on all collected messages.
		"""
		for tag in self.msgtags:
			self.chan.basic_ack (delivery_tag=tag)
		self.msgtags = []

	def nack (self, requeue=True):
		"""Send a basic_nack() on all collected messages.
		"""
		for tag in self.msgtags:
			self.chan.basic_nack (delivery_tag=tag, requeue=requeue)
		self.msgtags = []

	def more_to_collect (self):
		"""Call this to see if we should proceed; it means that
		   we collected at least one message, and nothing more
		   is available for immediate processing.
		"""
		# return len (self.msglist) == 0 or not self.empty
		#FAIL# print 'Length of collected messages:', len (self.msglist)
		#FAIL# print 'Number of waiting messages:', self.chan.get_waiting_message_count ()
		qhdl = self.chan.queue_declare (queue=self.queue, passive=True)
		# print 'qhdl.method.message_count =', qhdl.method.message_count
		#FAIL# return len (self.msglist) == 0 or self.chan.get_waiting_message_count () > 0
		return len (self.msglist) == 0 or qhdl.method.message_count > 0

	def collect (self, queue=None):
		"""Collect at least one message; if more can be collected
		   without waiting, then do so.  This method is not
		   re-entrant.  The queue defaults to the value that was
		   optionally set when this object was instantiated.
		"""
		regcb = False
		self.empty = False
		tout = None
		while self.more_to_collect ():
			# print 'There is more to collect...'
			# Note: self.chan is an instance of
			#    pika.adapters.blocking_connection.BlockingChannel
			#    which returns (None,None,None) for an empty queue
			#    or (mth,props,body) otherwise
			#FAIL# (mth, props, body) = self.chan.consume (
			#FAIL# 		queue=(queue or self.queue),
			#FAIL# 		inactivity_timeout=tout)
			(mth,props,body) = self.chan.basic_get (
						queue=(queue or self.queue))
			# print 'Class MTH =', type (mth)
			#TODO# No timeout... and bad reponses when empty!
			if type (mth) != pika.spec.Basic.GetOk:
				#TODO# raise Exception ('Unexpectedly found empty queue "' + (queue or self.queue) + '"')
				# print 'Unexpectedly found empty queue "' + (queue or self.queue) + '"'
				time.sleep (60)
				continue
			self.msgtags.append (mth.delivery_tag)
			self.msglist.append (body)
			# The next looping is not blocking
			tout = 10
			#TODO#FROMHERE#
			#TODO# self.callback_GetOk (self, self.chan, mth, props, body)
			#DROP# self.chan.basic_get (callback=self.callback_GetOk,
			#DROP# 		queue=(queue or self.queue))
			#DROP# if not regcb:
			#DROP# 	self.chan.add_callback (clx.callback_GetEmpty,
			#DROP# 		pika.spec.Basic.GetEmpty,
			#DROP# 		one_shot=True)
			#DROP# 	regcb = True
		pass # print 'There is nothing more to collect'

	def callback_GetEmpty (self, frame):
		"""Take note that no messages are currently available.
		"""
		self.gotempty = True

	def callback_GetOk (self, chan, mth, props, body):
		"""Take note of a new message.  Store its delivery_tag
		   for future use with self.ack() or self.nack().
		"""
		self.msgtags.append (mth.delivery_tag)
		self.msglist.append (body)


def open_client_connection (username=None, hostname='localhost'):
	"""Return a connection as an AMQP client, with the given
	   username.  A password is determined locally.  When
	   no username is provided, guest / guest will be used.
	   The default host to connect to is localhost, but
	   another value may be passed in.
	   The returned value is a connection, to be used as in

		cnx = open_client_connection (...)
		chan = cnx.channel ()
		...
		cnx.close ()

	   Exceptions that might be raised include

		pika.exceptions.AMQPChannelError
		pika.exceptions.AMQPError

	   See amqp_client_channel() for a "with" form.
	"""
	if username is not None:
		password = appcfg ['accounts'] [username]
		creds = pika.PlainCredentials (username, password)
	else:
		# Construct ConnectionParameters for guest / guest
		creds = None
	cnxparm = pika.ConnectionParameters (
		host=hostname,
		port=this_port,
		virtual_host=vhost,
		ssl=wrap_tls,
		ssl_options=conf_tls,
		credentials=creds
	)
	cnx = pika.BlockingConnection (cnxparm)
	return cnx

class amqp_client_channel ():
	"""Use this class in the "with" form:

		with amqp_client_channel (...) as chan:
			chan.basic_publish (...)

	   Set username to login in another way than guest / guest.
	   Set hostname to connect to another host than localhost.
	   Set transactional to request transactional behaviour.

	   Any AMQP exceptions will be caught, printed and fatally exited.

	   In the transactional variety, the channel is setup accordingly
	   and calls to tx_commit() and/or tx_rollback() are supported.
	   When normally ending the "with" clause, any remaining work will
	   be committed, and any failure to that end will be reported along
	   with the AMQP exceptions.  When the "with" clause is left early
	   due to an exception, than the transaction will be rolled back.
	"""

	def __init__ (self, username=None, hostname='localhost', transactional=False):
		self.username = username
		self.hostname = hostname
		self.transact = transactional

	def __enter__ (self):
		self.cnx = open_client_connection (self.username, self.hostname)
		self.chan = self.cnx.channel ()
		if self.transact:
			self.chan.tx_select ()
		return self.chan

	def __exit__ (self, typ, val, tbk):
		txfail = False
		if self.transact:
			if val is not None:
				self.chan.tx_rollback ()
			else:
				frame_method = self.chan.tx_commit ()
				txfail = type (frame_method.method) != pika.spec.Tx.CommitOk
		self.cnx.close ()
		if isinstance (val, pika.exceptions.AMQPChannelError):
			log_error ('AMQP Channel Error:', val)
			sys.exit (1)
		if isinstance (val, pika.exceptions.AMQPConnectionError):
			log_error ('AMQP Connection Error:', val)
			sys.exit (1)
		if isinstance (val, pika.exceptions.AMQPError):
			log_error ('AMQP Error:', val)
			sys.exit (1)
		if self.transact:
			if txfail:
				log_error ('AMQP Transaction Failure')
				sys.exit (1)

