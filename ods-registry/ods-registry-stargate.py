#!/usr/bin/env python2
#
# Perform DS changes as a Stargate reseller using their API
#
# Contact: Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
#
# Stargate currently supports DNSSEC for the following TLDs:
# .com, .net, .org


import os
import sys
import json
import urllib
import dns
import dns.name
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes.ANY.DS

from dns import dnssec

from syslog import *

import rabbitdnssec
from rabbitdnssec import log_debug, log_info, log_notice, log_warning, log_error, log_critical

cfg = rabbitdnssec.my_config ('ods-registry')


# Configuration
sg_api_authid		=	cfg ['registry_stargate_account']
sg_api_authkey		=	cfg ['registry_stargate_password']
sg_api_baseurl_domains	=	cfg ['registry_stargate_api_domains']
sg_api_baseurl_actions	=	cfg ['registry_stargate_api_actions']

# Debug output
def dbgprint(str):
	log_debug (str)

# Build Stargate API URL parameters
def build_sg_api_params(parameters):
	sg_api_params = ''
	sg_api_params += 'auth-userid={0}&api-key={1}'.format(sg_api_authid, sg_api_authkey)
	
	if len(parameters) > 0:
		sg_api_params += '&{0}'.format(urllib.urlencode(parameters))

	return sg_api_params

# Build the Stargate API GET URL for the specified command with the specified parameters
def build_sg_get_url(baseurl, command, parameters):
	sg_api_url = baseurl
	sg_api_url += command
	sg_api_url += '?'
	sg_api_url += build_sg_api_params(parameters)

	return sg_api_url

# Build the Stargate API POST URL for the specified command
def build_sg_post_url(baseurl, command):
	sg_api_url = baseurl
	sg_api_url += command

	return sg_api_url

# Convert an array of tag,value pairs to a Stargate "map"
def tvarray_to_sg_map(tvarray):
	resmap = []
	index = 1

	for tvalue in tvarray:
		resmap.append(('attr-name{0}'.format(index), tvalue[0]))
		resmap.append(('attr-value{0}'.format(index), tvalue[1]))

		index += 1

	return resmap

# Fetch JSON data using a GET
def sg_get_json(url):
	json_obj = None

	try:
		json_response = urllib.urlopen(url)
		json_obj = json.loads(json_response.read())
	except Exception,e:
		syslog(LOG_ERR, 'Failed to GET {0} ({1})'.format(url, e))
		
		raise Exception('Failed to GET {0} ({1})'.format(url, e))

	return json_obj

# Change data at Stargate using a POST
def sg_post_json(url, params):
	json_obj = None

	try:
		encoded_params = build_sg_api_params(params)
	
		dbgprint('Posting to "{0}" with POST data "{1}"'.format(url, encoded_params))

		json_response = urllib.urlopen(url, data=encoded_params)

		dbgprint('Response "{0}"'.format(json_response))

		json_obj = json.loads(json_response.read())
	except Exception, e:
		syslog(LOG_ERR, 'Failed to POST to {0} with parameters {1} ({2})'.format(url, params, e))
		
		raise Exception('Failed to POST to {0} with parameters {1} ({2})'.format(url, params, e))

	return json_obj

# Fetch domain information from Stargate for the specified domain
def fetch_domain_info(domain):
	# Stargate expects domain names without the trailing root label
	if domain.endswith('.'):
		domain = domain[:-1]

	cmd_url = build_sg_get_url(sg_api_baseurl_domains, 'details-by-name.json', [('domain-name',domain), ('options', 'OrderDetails'), ('options', 'DNSSECDetails')])

	json_data = sg_get_json(cmd_url)

	dbgprint('fetch_domain_info({0}) == "{1}"'.format(domain, json_data))

	return json_data

# Fetch the existing set of DS records as known to Stargate
def fetch_dsset(domain):
	# Fetch domain information from Stargate
	dominfo = fetch_domain_info(domain)

	if dominfo == None:
		syslog(LOG_ERR, 'Failed to retrieve information for {0}'.format(domain))
		raise Exception('Failed to retrieve information for {0}'.format(domain))
	elif 'status' in dominfo:
		syslog(LOG_ERR, 'Failed to retrieve information for {0}, Stargate returned "{1}: {2}"'.format(domain, dominfo['status'], dominfo['message']))
		raise Exception('Failed to retrieve information for {0}, Stargate returned "{1}: {2}"'.format(domain, dominfo['status'], dominfo['message']))

	# Convert domain info to DS records
	if 'dnssec' not in dominfo:
		syslog(LOG_INFO, '{0} has no DNSSEC data configured'.format(domain))
		return []

	ds_list = []

	for ds in dominfo['dnssec']:
		ds_list.append(dns.rdtypes.ANY.DS.DS(dns.rdataclass.IN, dns.rdatatype.DS, int(ds['keytag']), int(ds['algorithm']), int(ds['digesttype']), ds['digest'].decode("hex")))

	return ds_list

# Remove a DS through the Stargate API
def remove_ds(domain, orderid, ds):
	dbgprint('Removing a DS for "{0}"'.format(domain))

	parameters = [('order-id', orderid)]
	parameters += tvarray_to_sg_map(ds)

	remove_url_cmd = build_sg_post_url(sg_api_baseurl_domains, 'del-dnssec.json')

	dbgprint('Removing DS using URL "{0}" with parameters "{1}"'.format(remove_url_cmd, parameters))

	remove_ds_result = sg_post_json(remove_url_cmd, parameters)

	dbgprint('Result: "{0}"'.format(remove_ds_result))

	if remove_ds_result == None:
		syslog(LOG_ERR, 'Call to remove DS for {0} returned no result'.format(domain))
		raise Exception('Call to remove DS for {0} returned no result'.format(domain))
	elif 'status' in remove_ds_result and remove_ds_result['status'] != 'Success':
		syslog(LOG_ERR, 'Failed to remove a DS for {0}, Stargate returned "{1}: {2}"'.format(domain, remove_ds_result['status'], remove_ds_result['message']))
		raise Exception('Failed to remove a DS for {0}, Stargate returned "{1}: {2}"'.format(domain, remove_ds_result['status'], remove_ds_result['message']))

	syslog(LOG_INFO, 'Successfully removed a DS for {0} ({1})'.format(domain, ds))

# Add a DS through the Stargate API
def add_ds(domain, orderid, ds):
	dbgprint('Adding a DS for "{0}"'.format(domain))

	parameters = [('order-id', orderid)]
	parameters += tvarray_to_sg_map(ds)

	add_url_cmd = build_sg_post_url(sg_api_baseurl_domains, 'add-dnssec.json')

	dbgprint('Adding DS using URL "{0}" with parameters "{1}"'.format(add_url_cmd, parameters))

	add_ds_result = sg_post_json(add_url_cmd, parameters)

	dbgprint('Result: "{0}"'.format(add_ds_result))

	if add_ds_result == None:
		syslog(LOG_ERR, 'Call to add DS for {0} returned no result'.format(domain))
		raise Exception('Call to add DS for {0} returned no result'.format(domain))
	elif 'status' in add_ds_result and add_ds_result['status'] != 'Success':
		syslog(LOG_ERR, 'Failed to add a DS for {0}, Stargate returned "{1}: {2}"'.format(domain, add_ds_result['status'], add_ds_result['message']))
		raise Exception('Failed to add a DS for {0}, Stargate returned "{1}: {2}"'.format(domain, add_ds_result['status'], add_ds_result['message']))

	syslog(LOG_INFO, 'Successfully added a DS for {0} ({1})'.format(domain, ds))

# Fetch the number of pending actions for a domain in the Stargate system.
# As long as there are still DNSSEC actions pending, we should not be 
# pushing any new changes.
def get_no_of_pending_dnssec_actions(orderid):
	parameters = [('order-id', orderid)]
	parameters += [('no-of-records', 50)]
	parameters += [('page-no', 1)]
	parameters += [('action-type1', 'AddDNSSEC')]
	parameters += [('action-type2', 'DelDNSSEC')]

	cmd_url = build_sg_get_url(sg_api_baseurl_actions, 'search-current.json', parameters)

	json_data = sg_get_json(cmd_url)

	dbgprint('Current pending orders for order {0} "{1}"'.format(orderid, json_data))

	if json_data == None:
		return -1
	elif 'recsindb' in json_data:
		return int(json_data['recsindb'])
	elif json_data.get('status', None) == 'ERROR' and json_data.get('message', None) == 'No record found':
		syslog(LOG_INFO, 'No pending DNSSEC actions, proceeding')
		return 0
	else:
		syslog(LOG_ERR, 'Unexpected JSON data returned from search for pending actions ({0})'.format(json_data))
		return -1

# Update the DS set for a domain
def update_dsset(_sox, domain, new_dsset):
	toberemoved = []
	tobeadded = []

	old_dsset = fetch_dsset (domain)

	for ds in old_dsset:
		found = False

		for ds2 in new_dsset:
			found = found or ds._cmp(ds2) == 0

		if not found:
			hexdigest = ''

			for c in ds.digest:
				hexdigest += ('%02x' % ord(c))

			toberemoved.append([('keytag','{0}'.format(ds.key_tag)), ('algorithm', '{0}'.format(ds.algorithm)), ('digesttype', '{0}'.format(ds.digest_type)), ('digest', hexdigest)])

	for ds in new_dsset:
		found = False

		for ds2 in old_dsset:
			found = found or ds._cmp(ds2) == 0

		if not found:
			hexdigest = ''

			for c in ds.digest:
				hexdigest += ('%02x' % ord(c))

			tobeadded.append([('keytag','{0}'.format(ds.key_tag)), ('algorithm', '{0}'.format(ds.algorithm)), ('digesttype', '{0}'.format(ds.digest_type)), ('digest', hexdigest)])

	dbgprint('DS-set to be removed: {0}'.format(toberemoved))
	dbgprint('DS-set to be added: {0}'.format(tobeadded))

	if len(toberemoved) == 0 and len(tobeadded) == 0:
		dbgprint('No changes to the DS-set are required')
		return

	# Fetch domain information from Stargate
	dominfo = fetch_domain_info(domain)

	if dominfo == None:
		syslog(LOG_ERR, 'Failed to retrieve information for {0}'.format(domain))
		raise Exception('Failed to retrieve information for {0}'.format(domain))
	elif 'status' in dominfo:
		syslog(LOG_ERR, 'Failed to retrieve information for {0}, Stargate returned "{1}: {2}"'.format(domain, dominfo['status'], dominfo['message']))
		raise Exception('Failed to retrieve information for {0}, Stargate returned "{1}: {2}"'.format(domain, dominfo['status'], dominfo['message']))

	# We need the Stargate order number to be able to make changes, check
	# if it is present in the JSON data returned by the API
	if 'orderid' not in dominfo:
		raise Exception('Stargate did not return an order number for {0}, this is needed to update the DS set'.format(domain))

	if get_no_of_pending_dnssec_actions(dominfo['orderid']) != 0:
		raise Exception('It seems there are pending DNSSEC actions for {0}, bailing out'.format(domain))

	# Perform the required updates. Attempt to remove DS-es first, since
	# no DS is better than adding a broken DS.
	for ds in toberemoved:
		remove_ds(domain, dominfo['orderid'], ds)

	for ds in tobeadded:
		add_ds(domain, dominfo['orderid'], ds)

# Update the DNSKEY set for a domain
def update_keys(_sox, zone, newkeys):
	zonestr = zone.to_text ()

	if zonestr.endswith('.'):
		zonestr = zonestr[:-1]

	# TEST KLUDGE # FIXME #
	if zonestr != 'stampdns.org':
		log_debug('Not the test domain stampdns.org, skipping')
		return

	new_ds_set = []
	for key in newkeys:
		if key.flags & 0x0001:
			new_ds_set.append(dnssec.make_ds(zonestr + '.', key, 'SHA256'))
	update_dsset(_sox, zonestr, new_ds_set)

# Facilitation of main stream connection and disconnection as a generic pattern (moot for StarGate)
def connect ():
	return 'STARGATE SOCKET SUBSTITUTE'
def disconnect (_sox):
	pass

# Print status information for the specified domain
def print_domain_status(domain):
	log_info ('Status for', domain, 'is', fetch_dsset(domain))

# Main entry point for command-line use
def main():
	for domain in sys.argv[1:]:
		print_domain_status(domain)

# Open syslog
openlog ('ods-registry-stargate', LOG_PID | (LOG_PERROR if sys.stderr.isatty () else 0), LOG_USER)

# Run main entry point when invoked from the command-line
if __name__ == '__main__':
	main()

closelog()
