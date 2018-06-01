# Backend code for ods-registry, using the OpenDNSSEC signer
#
#TODO# Code is NOT TESTED yet, merely a scrap to start from


import rabbitdnssec
cfg = rabbitdnssec.my_config ('ods-registry')

zonelist_filename = cfg ['opendnssec']



#
# Start of code, imports
#
from lxml import etree


#
# Return the set of zone names
#
def zonenames ():
	#
	# Read the zone list file
	zonelist = open (zonelist_filename)
	zones = etree.parse (zonelist).getroot ()
	zonelist.close ()
	#
	# Collect the zone names mentioned in the zone list
	workset = set ()
	for zone in zones:
		if zone.tag != 'Zone':
			raise Exception ('Found something else than a Zone in the zonelist file ' + zonelist_filename)
		work = zone.attrib ['name']
		workset.add (work)
	return workset


#
# Signal having seen the DS
#
def seen_ds (zone, kid):
	exitcode = os.system ('sudo /usr/bin/ods-ksmutil key ds-seen --zone ' + zone + ' --keytag ' + str (kid))
	return exitcode
