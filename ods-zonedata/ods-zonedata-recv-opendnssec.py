# ods-zonedata-recv-opendnssec -- Backend for OpenDNSSEC
#
# This backend processes zone additions and removals in the zonelist.xml
# if not done yet, and it triggers the generation of .signconf files
# (in an atomic manner) for use with OpenDNSSEC.  This is a backend
# for the general ods-zonedata-recv logic.
#
# From: Rick van Rein <rick@openfortress.nl>


import os

import rabbitdnssec



# Specific configuration settings for OpenDNSSEC
#
cfg = rabbitdnssec.my_config ('opendnssec')
zonelist_file = cfg ['zonelist_file']
zonelist_file_tmp = zonelist_file + '.writing.' + str (os.getpid ())


import xml.etree.ElementTree as ET


def addzone (zone, zonedata):
	# No need to lock; this is the only process writing zonelist.xml
	tree = ET.parse (zonelist_file)
	zlist = tree.getroot ()
	zelem = zlist.find ('Zone[@name=\'' + zone + '\']')
	if zelem is not None:
		# Silently accept that the zone already exists
		return
	zdict = {
		'Policy': 'SURFdomeinen',
		'SignerConfiguration': '/var/opendnssec/signconf/' + zone + '.signconf'
	}
	zelem = ET.Element ('Zone', zdict)
	zlist.append (zelem)
	zadap = ET.Element ('Adapters', {})
	zelem.append (zadap)
	zadin = ET.Element ('Input', {})
	zadap.append (zadin)
	zadot = ET.Element ('Output', {})
	zadap.append (zadot)
	zadif = ET.Element ('File', {})
	zadif.text = '/var/opendnssec/unsigned/' + zone + '.txt'
	zadin.append (zadif)
	zadof = ET.Element ('File', {})
	zadof.txt = '/var/named/chroot/var/named/opendnssec/' + zone
	zadot.append (zadof)
	# Need to be atomic; asynchronous reads are still possible
	tree.write (zonelist_file_tmp)
	os.rename (zonelist_file_tmp, zonelist_file)

def delzone (zone):
	# No need to lock; this is the only process writing zonelist.xml
	tree = ET.parse (zonelist_file)
	zlist = tree.getroot ()
	zelem = zlist.find ('Zone[@name=\'' + zone + '\']')
	if zelem is None:
		# Silently accept that the zone was already removed
		return
	zlist.remove (zelem)
	# Need to be atomic; asynchronous reads are still possible
	tree.write (zonelist_file_tmp)
	os.rename (zonelist_file_tmp, zonelist_file)

