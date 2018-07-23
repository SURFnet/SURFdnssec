# Knot DNS backend for the ods-parenting-exchange
#
# Operations for adding and removing zones, as well
# as processing zone updates.
#
# This builds on a "default" template, which is kept
# incomplete so it can be decided independently if
# DNSSEC signing is used or not.  The ods-rpc daemon
# arranges the latter, by adding or removing a
# DNSSEC signing policy to a domain.  The "default"
# policy takes care of anything else.
#
# From: Rick van Rein <rick@openfortress.nl>


import os

import rabbitdnssec
from rabbitdnssec import log_debug, log_info, log_notice, log_warning, log_error, log_critical

cfg = rabbitdnssec.my_config ('knot')
upload_dir   = cfg ['upload_dir']
unsigned_dir = cfg ['unsigned_dir']
signed_dir   = cfg ['signed_dir']


#
# Return the signer input for a given zone name.
#
def unsigned_file (zone_name):
	return unsigned_dir + '/' + zone_name + '.txt'

#
# Return the signer output for a given zone name.
#
def signed_file (zone_name):
	return signed_dir + '/' + zone_name + '.txt'


# Add a zone for processing by Knot DNS
#
# Note: THIS CODE IS NOT USED.  IT RUNS IN ZONERECV INSTEAD.
#
def zone_add (zone, knot_zone_file):
	raise NotImplementedError ('Add zones in ods-zonerecv instead of in ods-parenting-exchange')
	return
	#TODO#HERE-OR-DURING-RECV#
	rv0 = os.system ('/usr/sbin/knotc conf-begin')
	if rv0==0:
		rv1 = os.system ('/usr/sbin/knotc conf-set zone.domain "' + zone + '"')
		# Ignore the result, as it may be taken care of already
		if rv1 != 0:
			rv1 = 0
	if rv0==0 and rv1==0:
		try:
			fd = open (knot_zone_file, 'w')
			fd.write (zone + ' 300 IN SOA ns1.' + zone + ' dns-beheer.' + zone + ' 0 300 300 300 300\n')
			fd.close ()
			rv2 = 0
		except:
			rv2 = 2
	if rv0==0 and rv1==0 and rv2==0:
		os.system ('/usr/sbin/knotc conf-commit')
	else:
		os.system ('/usr/sbin/knotc conf-abort')
		log_error ('Knot DNS could not add zone', zone)

# Remove a zone from processing by Knot DNS
#
# Note: THIS CODE IS NOT USED.  IT RUNS IN ZONERECV INSTEAD.
#
def zone_del (zone):
	raise NotImplementedError ('Delete zones in ods-zonerecv instead of in ods-parenting-exchange')
	return
	#TODO#HERE-OR-DURING-RECV#
	rv0 = os.system ('/usr/sbin/knotc conf-begin')
	if rv0 == 0:
		rv1 = os.system ('/usr/sbin/knotc conf-unset zone.domain "' + zone + '"')
	if rv0==0 and rv1==0:
		rv2 = os.system ('/usr/sbin/knotc zone-purge "' + zone + '"')
	if rv0==0 and rv1==0 and rv2==0:
		os.system ('/usr/sbin/knotc conf-commit')
	else:
		os.system ('/usr/sbin/knotc conf-abort')
		log_error ('Knot DNS could not delete zone', zone)

# Update a zone being processed by Knot DNS
#
def zone_update (zone, new_zone_file, knot_zone_file):
	log_debug ('CMD> ldns-zonediff -k -o "' + zone + '" "' + knot_zone_file + '" "' + new_zone_file + '" | /usr/sbin/knotc')
	os.system ('ldns-zonediff -k -o "' + zone + '" "' + knot_zone_file + '" "' + new_zone_file + '" | /usr/sbin/knotc')
	# ignore previous result, but check the result
	tmp_zone_file = '/tmp/' + zone
	log_debug ('CMD> /usr/sbin/knotc zone-read "' + zone + '" | sed \'s/^\[[^]]*\] *//\' > "' + tmp_zone_file + '"')
	os.system ('/usr/sbin/knotc zone-read "' + zone + '" | sed \'s/^\[[^]]*\] *//\' > "' + tmp_zone_file + '"')
	log_debug ('CMD> ldns-zonediff -o "' + zone + '" "' + tmp_zone_file + '" "' + new_zone_file + '"')
	exitval = os.system ('ldns-zonediff -o "' + zone + '" "' + tmp_zone_file + '" "' + new_zone_file + '"')
	if exitval != 0:
		log_error ('Knot DNS has not received/processed complete zone file update for', zone)

