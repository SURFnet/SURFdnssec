
#TODO# This is a scrap of code that hasn't been fully tested


import rabbitdnssec
from rabbitdnssec import log_debug, log_info, log_notice, log_warning, log_error, log_critical

cfg = rabbitdnssec.my_config ('opendnssec')
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


#
# Send a signer hint, possible for a specific zone.
#
def signer_hint (zone_name=''):
	cmd = 'ods-signer sign ' + zone_name
	log_debug ('Hinting signer with:', cmd)
	exitval = os.system (cmd)
	if exitval != 0:
		log_error ('Signer hint failed: ' + cmd)

#TODO# CAN USE THIS OLDER CODE FOR ZONE UPDATES:

		if sign_text != zone_text:
			os.rename (sign_path + '.prepublish', sign_path)
			signer_hint (zone_name=self.zone_name)


#
# Check if a zone is known
#
def zone_exists (zone_name=''):
	signed_path = signed_file (zone_name)
	try:
		signed_text = os.stat (signed_path)
		return True
	except:
		#MOVED#OUT# backendmod.zone_add (self.zone_name, sign_path)
		log_error ('Have no signed zone file in', signed_path)
		return False

