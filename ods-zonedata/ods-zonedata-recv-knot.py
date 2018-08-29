# ods-zonedata-recv-knot -- Backend for Knot DNS
#
# This backend processes zone additions and removals in the database
# that tracks Knot DNS' zones, if not done yet.  This is a backend
# for the general ods-zonedata-recv logic.
#
# This process has interactions with ods-keyops-knot-addkey and
# ods-keyops-knot-delkey, to add and remove keys orthogonally, in
# spite of Knot DNS resisting such an approach.
#
# From: Rick van Rein <rick@openfortress.nl>


import os

import stat

import rabbitdnssec
from rabbitdnssec import log_debug, log_info, log_notice, log_warning, log_error, log_critical


def addzone (zone):
	# Ensure that a zone is served by Knot DNS.
	# Note: Key setup and DNSSEC signing is orthogonally setup;
	# it defaults to being off, so an unsigned zone is delivered.
	#
	# Note: This procedure is idempotent, zone additions are neutral
	# for already-existing zones.
	#
	# Note: Zone addition is not done in the parenting procedure,
	# as it makes little sense there without actual zone data (with,
	# at minimum, the SOA record).  The parenting exchange will get
	# a hint when we add a zone though, so it can append any child
	# name server records as soon as we add the zone.
	#
	global_lock = open ('/tmp/knotc-global-lock', 'w')
	fcntl.lockf (global_lock, fcntl.LOCK_EX)
	rv0 = os.system ('/usr/sbin/knotc conf-begin')
	rv1 = 0
	rv2 = 0
	if rv0==0:
		os.system ('/usr/sbin/knotc conf-set zone.domain "' + zone + '"')
		# Ignore the result; the zone may already exist; check that
		rv1 =  os.system ('/usr/sbin/knotc conf-get "zone[' + zone + ']"')
	if rv0==0 and rv1==0:
		try:
			knot_presig = '/var/opendnssec/signed/' + zone + '.txt'
			knot_signed = '/var/opendnssec/signed/' + zone + '.txt'
			shared = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP
			log_debug ('Writing to', knot_presig)
			fd = open (knot_presig, 'w')
			fd.write (zone + '. 300 IN SOA ns1.' + zone + '. dns-beheer.' + zone + '. 0 300 300 300 300\n')
			fd.write (zone + '. 300 IN TXT "TODO" "Need actual content"\n')
			fd.write (zone + '. 300 IN NS ns1.todo.\n')
			fd.write (zone + '. 300 IN NS ns2.todo.\n')
			fd.close ()
			os.chmod (knot_presig, shared)
			fd = open (knot_signed, 'w')
			fd.write (zone + '. 300 IN SOA ns1.' + zone + '. dns-beheer.' + zone + '. 0 300 300 300 300\n')
			fd.write (zone + '. 300 IN TXT "TODO" "Need actual content"\n')
			fd.write (zone + '. 300 IN NS ns1.todo.\n')
			fd.write (zone + '. 300 IN NS ns2.todo.\n')
			fd.close ()
			os.chmod (knot_signed, shared)
			rv2 = os.system ('/usr/sbin/knotc conf-set "zone[' + zone + '].file" "' + knot_signed + '"')
		except:
			rv2 = 2
	if rv0==0 and rv1==0 and rv2==0:
		os.system ('/usr/sbin/knotc conf-commit')
		log_debug ('CMD> ods-keyops-knot-sharekey "' + zone + '"')
		os.system ('ods-keyops-knot-sharekey "' + zone + '"')
	else:
		if rv0==0:
			os.system ('/usr/sbin/knotc conf-abort')
		log_error ('Knot DNS could not add zone', zone, '(%d,%d,%d)' % (rv0,rv1,rv2))
	global_lock.close ()

def delzone (zone):
	# Remove a zone from Knot DNS, so it is no longer served.
	# Note: The removal is even done when key material still
	# exists.  In this case, the zone is no longer delivered
	# but the key material is assumed to be cleaned up by an
	# orthogonal process [that will shrug if the zone has
	# been removed already].
	#
	# Note: Zone deletion is not done in the parenting procedure,
	# as it can silently ignore the case of a deleted zone (for which
	# we need, at minimum, the SOA record).  The parenting exchange
	# needs no hint when we delete a zone.
	#
	global_lock = open ('/tmp/knotc-global-lock', 'w')
	fcntl.lockf (global_lock, fcntl.LOCK_EX)
	rv0 = os.system ('/usr/sbin/knotc conf-begin')
	rv1 = 0
	rv2 = 0
	if rv0==0:
		rv1 = os.system ('/usr/sbin/knotc conf-unset zone.domain "' + zone + '"')
	if rv0==0 and rv1==0:
		rv2 = os.system ('/usr/sbin/knotc -f zone-purge "' + zone + '"')
	if rv0==0 and rv1==0 and rv2==0:
		os.system ('/usr/sbin/knotc conf-commit')
	else:
		if rv0==0:
			os.system ('/usr/sbin/knotc conf-abort')
		log_error ('Knot DNS could not delete zone', zone, '(%d,%d,%d)' % (rv0,rv1,rv2))
	global_lock.close ()

