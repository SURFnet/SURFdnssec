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
	rv0 = os.system ('knotc conf-begin')
	rv1 = 0
	rv2 = 0
	if rv0==0:
		os.system ('knotc conf-set zone.domain "' + zone + '"')
		# Ignore the result; the zone may already exist; check that
		rv1 =  os.system ('knotc conf-get "zone[' + zone + ']"')
	if rv0==0 and rv1==0:
		try:
			knot_presig = '/var/opendnssec/signed/' + zone + '.txt'
			knot_signed = '/var/opendnssec/signed/' + zone + '.txt'
			print 'Writing to', knot_presig
			fd = open (knot_presig, 'w')
			fd.write (zone + ' 300 IN SOA ns1.' + zone + ' dns-beheer.' + zone + ' 0 300 300 300 300\n')
			fd.write (zone + ' 300 IN TXT "TODO" "Need actual content"\n')
			fd.close ()
			fd = open (knot_signed, 'w')
			fd.write (zone + ' 300 IN SOA ns1.' + zone + ' dns-beheer.' + zone + ' 0 300 300 300 300\n')
			fd.write (zone + ' 300 IN TXT "TODO" "Need actual content"\n')
			fd.close ()
			rv2 = os.system ('knotc conf-set "zone[' + zone + '].file" "' + knot_signed + '"')
		except:
			rv2 = 2
	if rv0==0 and rv1==0 and rv2==0:
		os.system ('knotc conf-commit')
	else:
		if rv0==0:
			os.system ('knotc conf-abort')
		#TODO# Report that Knot DNS could not add zone
		print 'TODO: ERROR: Knot DNS could not add zone', zone, '(%d,%d,%d)' % (rv0,rv1,rv2)

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
	rv0 = os.system ('knotc conf-begin')
	rv1 = 0
	rv2 = 0
	if rv0==0:
		rv1 = os.system ('knotc conf-unset zone.domain "' + zone + '"')
	if rv0==0 and rv1==0:
		rv2 = os.system ('knotc zone-purge "' + zone + '"')
	if rv0==0 and rv1==0 and rv2==0:
		os.system ('knotc conf-commit')
	else:
		if rv0==0:
			os.system ('knotc conf-abort')
		#TODO# Report that Knot DNS could not delete zone
		print 'TODO: ERROR: Knot DNS could not delete zone', zone, '(%d,%d,%d)' % (rv0,rv1,rv2)

