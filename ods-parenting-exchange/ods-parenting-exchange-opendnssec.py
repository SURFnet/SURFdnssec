
#TODO# This is a scrap of code that hasn't been fully tested


import rabbitdnssec

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
	print 'DEBUG: Hinting signer with:', cmd
	exitval = os.system (cmd)
	if exitval != 0:
		sys.stderr.write ('Signer hint failed: ' + cmd + '\n')

#TODO# CAN USE THIS OLDER CODE FOR ZONE UPDATES:

		if sign_text != zone_text:
			os.rename (sign_path + '.prepublish', sign_path)
			signer_hint (zone_name=self.zone_name)

