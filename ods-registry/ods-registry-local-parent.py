# Registry module for local parenting
#
# This module sends a DNSKEY set to the parenting exchange.
# There it is assumed to lead to useful interactions.
# Since this is always done with a stripped version of the
# original zone, namely its parent, there should be and end
# to any recursion this might yield.
#
# From: Rick van Rein <rick@openfortress.nl>


import os
import sys
import socket
import ssl

import pika

import rabbitdnssec


exchange_name = rabbitdnssec.my_exchange ('parenting')


#
# Return a socket / handle for the connection to the local parent
#
def connect ():
	#
	# Create the queueing infrastructure for the parent exchange.
	#
	creds = rabbitdnssec.my_creds (ovr_username='uplink')
	print 'Connection parameters:', cnxparm
	intcnx = None
	chan = None
	try:
		intcnx = pika.BlockingConnection (cnxparm)
		chan = intcnx.channel ()
		#TODO:CLASS# chan.basic_consume (process_msg, queue=queue_name)
		#TODO:NOTHERE# print 'Starting transaction'
		#TODO:NOTHERE# chan.tx_select ()
		#TODO:CLASS# print 'Basically consuming!'
		#TODO:CLASS# chan.start_consuming ()
		#TODO:CLASS# print 'Done consuming; committing transaction'
		return (intcnx,chan)
	except pika.exceptions.AMQPChannelError, e:
		print 'AMQP Channel Error:', e
		sys.exit (1)
	except pika.exceptions.AMQPError, e:
		print 'AMQP Error:', e
		sys.exit (1)

#
# Terminate any outstanding connection to the local parent
#
def disconnect (cnx):
	(intcnx,chan) = cnx
	#
	# To end this program, unwind all instances and unregister our own
	# callback to cb_uploaded_hint().
	#
	self.basic_cancel (uploaded_hints_tag)
	for pex in parenting_exchange.values ():
		pex.close ()
	chan = None
	intcnx.close ()
	intcnx = None

#
# Pass a set of DNSSEC keys to the parent
#
def update_keys (cnx, domain, keys):
	(intcnx,chan) = cnx
	dnskeys = map (lambda k: '3600 IN DNSKEY ' + k.to_text (), keys)
	msg = ''.join (dnskeys).strip ()
	print 'Local "registry" update with keys', msg
	self.chan.basic_publish (exchange=exchange_name,
			routing_key=domain,
			body=msg)

