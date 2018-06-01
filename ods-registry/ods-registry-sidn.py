#!/usr/bin/python
#
# registry_shell.py -- Connect to a registry and run commands.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys

import rabbitdnssec


cfg = rabbitdnssec.my_config ('ods-registry')


# Read configuration
#
sidn_host =      cfg ['registry_sidn_host']
sidn_port = int (cfg ['registry_sidn_port'])
sidn_user =      cfg ['registry_sidn_account']
sidn_pass =      cfg ['registry_sidn_password']
sidn_root =      cfg ['registry_sidn_calist']
sidn_lock =      cfg ['registry_sidn_epplock']


# Check invocation when called as main script
#
#TODO# Perhaps skip configuration file parsing for main script?
#
server_tuple = None
if __name__ == '__main__':
	if len (sys.argv) > 3:
		log_error ('Usage: ' + sys.argv [0] + ' [<registry> [<port>]]\n')
		sys.exit (1)
	try:
		if len (sys.argv) >= 2:
			# Override hostname
			sidn_host =      sys.argv [1]
		if len (sys.argv) >= 3:
			# Override port
			sidn_port = int (sys.argv [2])
	except:
		log_error ('Registry ' + sys.argv [1] + ':' + sys.argv [2] + ' is unknown\n')
		sys.exit (1)


#
# A few oft-used strings as an easy-to-use (constant-value) variable
#
xml_head = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
epp_open = '<epp xmlns="urn:ietf:params:xml:ns:epp-1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">\n'
epp_clos = '</epp>\n'

eppns = 'urn:ietf:params:xml:ns:epp-1.0'
dnssecns = 'urn:ietf:params:xml:ns:secDNS-1.1'
sidnresultns = 'http://rxsd.domain-registry.nl/sidn-ext-epp-1.0'


#
# The number of arguments for each recognised command, grouped by the
# shellname.  The shellname is this script's basename, so through links
# the available command set can be altered.
#
action_argcount = {

        'registry_shell': {
                'keysync': 1,
                'eppkeys': 1,
                'exit': 0,
                'quit': 0,
                'help': 0,
        },

}


import os
import os.path
import re
import time
from syslog import *

import base64
import dns
import dns.name
import dns.resolver
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY
import dns.rdtypes.ANY.DNSKEY

import socket
import ssl
import struct
import fcntl



#
# Report an error and quit with an error code
#
def fatal (errstr):
        log_error ('Fatal error:', errstr, '-- Closing shell with force')
        closelog ()
        sys.exit (1)


#
# Run a command; show "OK" unless "more" is set to indicate more commands follow
# Commands are run through sudo, to obtain the right privileges.
#
def runcmd (cmdline, more=False):
        syslog (LOG_INFO, 'Running: ' + cmdline)
        retval = os.system ('sudo ' + cmdline)
        if retval != 0:
                fatal ('Error: ' + str (retval) + '\n')
        elif not more:
                log_debug ('OK\n')


#
# Print a prompt if the standard input is an interactive terminal:
#
def prompt ():
        if os.isatty (sys.stdin.fileno ()):
                log_debug (shellname + '$ ')



from lxml import etree


#
# Globals
#

# Greeting from server, result of last <hello/>
greetz = None
hostname = None


#
# Create a TLS-wrapped connection to the registration server
#
def connect ():
	global sidn_host, sidn_port, sidn_root
        try:
                sox = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
                soxplus = ssl.wrap_socket (sox, ca_certs=sidn_root, cert_reqs=ssl.CERT_REQUIRED)
                soxplus.connect ( (sidn_host,sidn_port) )
		hello (soxplus)
		login (soxplus)
                return soxplus
        except:
                log_error ('Failed to securely connect to server %s:%d\n' % (sidn_host,sidn_port))
                raise

#
# Drop a TLS-wrapped connection to the registration server
#
def disconnect (sox):
	logout (sox)


#
# Send a message, await the reply synchronously and return it
#
def syncio (sox, query):
        try:
                if query:
                        #DEBUG_SHOWS_PASSWORD# sys.stdout.write (query)
                        query = struct.pack ('>L', 4 + len (query)) + query
                        sox.send (query)
                else:
                        log_debug ('Picking up response without sending a query\n')
        except:
                log_error ('Failed to send message to registry server\n')
                raise
        try:
                resplen = struct.unpack ('>L', sox.read (4)) [0] - 4
                # syslog (LOG_DEBUG, 'Receiving %d response bytes from registry' % resplen)
                xmltext = ''
                while len (xmltext) < resplen:
                        xmltext = xmltext + sox.read (resplen - len (xmltext))
		#DEBUG_SHOWS_ANYTHING# sys.stdout.write (xmltext)
        except:
                log_error ('Failed to receive reply from registry server\n')
                raise
        try:
                xmltree = etree.fromstring (xmltext)
                return xmltree
        except:
                log_error ('Failed to parse XML:\n| ' + xmltext.replace ('\n', '\n| '))
                raise


#
# Check if a response (to a command) is OK.
# Note that some error codes are quite acceptable, such as
# "object not found" in response to deletion.  Such codes
# can be added through the "extra" string parameter.
#
# Return True for okay, or False otherwise.
#
def response_ok (resp, extra=None):
        if resp.tag != '{' + eppns + '}epp':
                return False
        result = resp.find ('{' + eppns + '}response/{' + eppns + '}result')
        if result is None:
                return False
        if not result.attrib.has_key ('code'):
                return False
        rescode = result.attrib ['code']
        if rescode [:1] != '1' and rescode != extra:
                return False
        return True


#
# Raise an exception that incorporates an error message
# and an XML text.
#
def raise_xml (errstr, xml):
        try:
                rescode = xml.find ('{' + eppns + '}response/{' + eppns + '}result').attrib ['code']
                resmesg = xml.find ('{' + eppns + '}response/{' + eppns + '}result/{' + eppns + '}msg').text
                errstr = errstr + ': ' + rescode + ' ' + resmesg
		try:
			for cond in xml.find ('{' + eppns + '}response/{' + eppns + '}extension/{' + sidnresultns + '}ext/{' + sidnresultns + '}response/{' + sidnresultns + '}msg'):
				rescode = rescode + '.' + cond.attrib ['code']
				resdetl = cond.text
				errstr = errstr + ' -- ' + reslevl + ' ' +rescode + ': ' + resmesg + ' (' + resdetl + ')'
		except:
			pass
        except Exception, e:
                errstr = errstr + ':\n| ' + etree.tostring (xml).replace ('\n', '\n| ')
                if errstr [-3:] == '\n| ':
                        errstr = errstr [:-2]
                errstr = errstr + 'Plus, ' + str (e) + '\n'

        syslog (LOG_CRIT, errstr)
        raise Exception (errstr)


#
# Check if a response is ok, just as with response_ok()
# but raise an error string if the result is False.
#
def require_ok (errstr, resp, extra=None):
        if not response_ok (resp, extra):
                raise_xml (errstr, resp)


#
# Return a keyData XML string for the given key
#
def keydata_xmlstring (key):
	key64 = base64.standard_b64encode (key.key)
	return ("""
	<secDNS:keyData>
		<secDNS:flags>"""    + str (key.flags)     + """</secDNS:flags>
		<secDNS:protocol>""" + str (key.protocol)  + """</secDNS:protocol>
		<secDNS:alg>"""      + str (key.algorithm) + """</secDNS:alg>
		<secDNS:pubKey>"""   + key64               + """</secDNS:pubKey>
	</secDNS:keyData>
""")


#
# Return a dsData XML string for the given key
# The zone is a dns.name object; the key is a dns.rdtypes.ANY.DNSKEY object.
# The algorithm is mentioned by name.  The embedkeydata option can be
# provided to indicate if an optional <secDNS:keyData/> should be embedded.
#
def dsdata_xmlstring (zone, key, alg='SHA1', embedkeydata=True):
	keyds = dns.dnssec.make_ds (zone, key, alg)
	hexdigest = ''
	for c in keyds.digest:
		hexdigest = hexdigest + ('%02x' % ord (c))
	return ("""
	<secDNS:dsData>
		<secDNS:keyTag>"""     + str (keyds.key_tag)     + """</secDNS:keyTag>
		<secDNS:alg>"""        + str (keyds.algorithm)   + """</secDNS:alg>
		<secDNS:digestType>""" + str (keyds.digest_type) + """</secDNS:digestType>
		<secDNS:digest>"""     + hexdigest               + """</secDNS:digest>
	""" + (keydata_xmlstring (key) if embedkeydata else '') + """
	</secDNS:dsData>
""")


#
# Send a "hello" greeting and store the reply in greetz
#
def hello (sox):
        global greetz, hostname
        greetz = syncio (sox,
xml_head +
epp_open +
"""     <hello/>
""" +
epp_clos)
        syncio (sox, None)
        hostname = greetz.find ('{' + eppns + '}greeting/{' + eppns + '}svID').text


#
# Send a keepalive message while nothing else is going on
#
keepalive = hello


#
# Login to the server, after the usual greetings phase
#
def login (sox):
        # print 'Login in progress:'
        resp = syncio (sox,
xml_head +
epp_open +
"""     <command>
                <login>
                        <clID>""" + sidn_user + """</clID>
                        <pw>"""   + sidn_pass + """</pw>
                        <options>
                                <version>1.0</version>
                                <lang>en</lang>
                        </options>
			<svcs>
				<objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
				<objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
				<objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
				<svcExtension>
					<extURI>http://rxsd.domain-registry.nl/sidn-ext-epp-1.0</extURI>
				</svcExtension>
			</svcs>
                </login>
        </command>
""" +
epp_clos)
        require_ok ('Failed to login to EPP server ' + hostname, resp)


#
# Logout from the server
#
def logout (sox):
        # print 'Logging out...'
        resp = syncio (sox,
xml_head +
epp_open +
"""     <command>
                <logout/>
        </command>
""" +
epp_clos)
        require_ok ('Failed to logout from EPP server ' + hostname, resp, '1500')
        # print 'Logged out.'


#
# Update from the old to the new set of keys for a given zone.
# Either key set may be empty, to signify moving from/to an
# unsigned zone reference in the parent zone.
#
def update_keys (sox, zone, newkeys):
	worktodo = False
	zonestr = zone.to_text ()
	if zonestr [-1:] == '.':
		zonestr = zonestr [:-1]
	#
	# Retrieve the old/current keys over EPP
	oldkeys = eppkeys (sox, zonestr)
	#
	# Start construction of the EPP command
	query = (
xml_head +
epp_open +
"""	<command>
		<update>
			<domain:update xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
				<domain:name>""" + zonestr + """</domain:name>
			</domain:update>
		</update>

		<extension>
			<secDNS:update xmlns:secDNS=\"""" + dnssecns + """\">

""")
	#
	# Remove any old keys that are missing in the new set
	toberemoved = ''
	for key in oldkeys:
		found = False
		for key2 in newkeys:
			found = found or key._cmp (key2) == 0
		if not found:
			# toberemoved = toberemoved + dsdata_xmlstring (zone, key, embedkeydata=False)
			toberemoved = toberemoved + keydata_xmlstring (key)
			worktodo = True
	if toberemoved != '':
		query = query + '<secDNS:rem>\n' + toberemoved + '</secDNS:rem>\n'
	#
	# Add any new keys that are not in the old set
	tobeadded = ''
	for key in newkeys:
		found = False
		for key2 in oldkeys:
			found = found or key._cmp (key2) == 0
		if not found:
			# tobeadded = tobeadded + dsdata_xmlstring (zone, key, embedkeydata=False)
			tobeadded = tobeadded + keydata_xmlstring (key)
			worktodo = True
	if tobeadded != '':
		query = query + '<secDNS:add>\n' + tobeadded + '</secDNS:add>\n'
	#
	# Finish construction of the EPP command
	query = (query +
"""			</secDNS:update>
		</extension>
	</command>
""" + epp_clos)
	#
	# Execute the EPP command
	if worktodo:
		resp = syncio (sox, query)
		require_ok ('Failed to update the key set in the parent', resp)



#
# Setup a resolver instance for localhost
#
rescf = os.popen ('echo nameserver 127.0.0.1', 'r')
local_resolver = dns.resolver.Resolver (configure=False)
local_resolver.read_resolv_conf (rescf)
local_resolver.use_edns (0, 0, 4096)


#
# Obtain the list of keys in use according to EPP
#
def eppkeys (sox, zonestr):
        # print 'EPP download of current keyset in progress:'
        resp = syncio (sox,
xml_head +
epp_open +
"""     <command>
                <info>
			<domain:info xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
				<domain:name hosts="all">""" + zonestr + """</domain:name>
			</domain:info>
                </info>
        </command>
""" +
epp_clos)
        require_ok ('Failed to obtain domain info for ' + zonestr, resp)
	eppkeys = []
	for xk in resp.findall ('{' + eppns + '}response/{' + eppns + '}extension/{' + dnssecns + '}infData/{' + dnssecns + '}keyData'):
		flags = int (xk.find ('{' + dnssecns + '}flags').text)
		if flags & dns.rdtypes.ANY.DNSKEY.SEP != 0:
			proto = int (xk.find ('{' + dnssecns + '}protocol').text)
			alg = int (xk.find ('{' + dnssecns + '}alg').text)
			key = base64.standard_b64decode (xk.find ('{' + dnssecns + '}pubKey').text)
			k = dns.rdtypes.ANY.DNSKEY.DNSKEY (dns.rdataclass.IN, dns.rdatatype.DNSKEY, flags, proto, alg, key)
			eppkeys.append (k)
	return eppkeys


#
# Obtain the list of keys for a domain, and add them
#
# Note: This assumes that the SEP bit is not just a hint, but actually
#       used if and only if a key fulfills the role of secure entry point,
#	also known as a key signing key.  This is the case with OpenDNSSEC,
#	but it may or may not hold for additional keys imported.
#
def keysync (sox, zonestr):
	newkeys = []
	#TODO# Handle empty lists if none present, but beware of timeouts
	zone = dns.name.from_text (zonestr)
	#CLASS# keys = local_resolver.query (zone, rdtype=dns.rdtypes.ANY.DNSKEY)
	keys = local_resolver.query (zone, rdtype=48)	# DNSKEY
	for k in keys:
		if k.flags & dns.rdtypes.ANY.DNSKEY.SEP != 0:
			newkeys.append (k)
	#TMP# update_keys (sox, zone, [], newkeys)
	oldkeys = eppkeys (sox, zonestr)
	update_keys (sox, zone, oldkeys, newkeys)


#
# The main program for the shell
#
def shell_session (cnx):
        global shellname, action_argcount, sidn_host, sidn_port, sidn_user, sidn_pass
        shellname = 'registry_shell'

        openlog ('registry_shell', LOG_PID | (LOG_PERROR if sys.stderr.isatty () else 0), LOG_DAEMON)
        syslog (LOG_INFO, 'Opening new shell to ' + sidn_host + ':' + str (sidn_port))
        loggedin = False

        last_contact = None
        last_user = None

        try:
                login (cnx)
                loggedin = True
                moretodo = True
                while moretodo:
                        prompt ()
                        cmd = sys.stdin.readline ()
                        if cmd == '':
                                log_debug ('exit\nOK\n')
                                break
                        if cmd == '\n' or cmd [:1] == '#':
                                continue
                        cmd = cmd.strip ()
                        syslog (LOG_INFO, 'Received: ' + cmd)
                        while cmd.find ('  ') != -1:
                                cmd = cmd.replace ('  ', ' ')
                        argv = cmd.split (' ')
                        if not action_argcount [shellname].has_key (argv [0]):
                                fatal ('Command not allowed')
                        if len (argv) != 1 + action_argcount [shellname] [argv [0]]:
                                fatal ('Wrong args')

			elif argv [0] == 'keysync':
				keysync (cnx, argv [1])

			elif argv [0] == 'eppkeys':
				keyset = eppkeys (cnx, argv [1])
				ctr = 0
				for key in keyset:
					# print key.to_text ()
					ctr = ctr + 1
				log_debug ('Number of KSK keys found: ', ctr)

                        elif argv [0] == 'help' and os.isatty (sys.stdin.fileno ()):
                                prefix  = 'Supported commands: '
                                for cmd in action_argcount [shellname].keys ():
                                        log_debug (prefix + cmd)
                                        prefix = ', '
                                log_debug ('\nOK\n')

                        elif argv [0] == 'exit' or argv [0] == 'quit':
                                log_debug ('OK\n')
                                moretodo = False

                        else:
                                fatal ('Unknown command')

        except SystemExit:
                raise


        except Exception, e:
                syslog ('Shell exception: ' + str (e))
                fatal ('You hurt my feelings -- this is goodbye')
                sys.exit (1)

        finally:
                if loggedin:
                        logout (cnx)

        syslog (LOG_INFO, 'Closing shell regularly')
        closelog ()




#
# Main program -- running inside flock()
#
if __name__ == '__main__':
	cnx = connect ()
	# print 'Connected to %s:%d' % server_tuple
	syslog (LOG_INFO, 'Registry server date:' + greetz.find ('{' + eppns + '}greeting/{' + eppns + '}svDate').text)
	lockf = open (sidn_lock, 'w')
	try:
		fcntl.flock (lockf, fcntl.LOCK_EX)
		shell_session (cnx)
	finally:
		os.unlink (sidn_lock)
		lockf.close ()
		disconnect (cnx)



