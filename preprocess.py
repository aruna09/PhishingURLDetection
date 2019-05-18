import tldextract as tld
import re
import whois # runs in python3
import dns.resolver
import pageRank #paeRank algorithm(program) not written by me
import requests
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError
import json
from time import strptime
import datetime as dt
import  urllib, sys, re
import xmltodict, json
import datetime
import dns.resolver

fakeURL = 'http://125.98.3.123/fake.html'
correctURL = 'http://google.com'
testFeature = []

# ---------------Address bar based features------------------
def havingIPAddress():
	"""checks if has IP Address"""

	extract = tld.extract(fakeURL)
	domainName = extract.domain
	c=0

	for character in domainName:
		if character=='.':
			c=c+1

	if c==3:
		testFeature.append(-1)
	else:
		testFeature.append(1)
	

def checkLengthOfURL():
	"""Phishers use long fakeURL to hide the doubtful part in the address bar. The fakeURL lenght is checked with the 
	average length and used as condition to cross check."""
	if len(fakeURL)<54:
		testFeature.append(1);
	elif len(fakeURL)>=54 and len(fakeURL)<75:
		testFeature.append(0);
	else:
		testFeature.append(-1);

def checkTinyURL():
	extract = tld.extract(fakeURL)
	domain = extract.domain
	suffix = extract.suffix
	if domain=="bit" and suffix=="ly":
		testFeature.append(-1)
	else:
		testFeature.append(1)

def checkAtSymbol():
	"""Using “@” symbol in the fakeURL leads the browser to ignore everything preceding
		the “@” symbol and the real address often follows the “@” symbol.""" 
	check = re.findall(r"@", fakeURL)
	if len(check)>0:
		testFeature.append(-1)
	else:
		testFeature.append(1)


def checkRedirects():
	"""The existence of “//” within the URL path means that the user will be redirected to another website. 
	An example of such URL’s is: “http://www.legitimate.com//http://www.phishing.com”. We examin the 
	location where the “//” appears. The function finds if the URL starts with “HTTP”, that means the “//” should 
	appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position."""
	expr = "[//]"
	p = re.compile(expr)
	iterator = p.finditer(expr)
	for match in iterator:
		lastIndex = match.end()

	if lastIndex > 7:
		testFeature.append(-1)
	else:
		testFeature.append(1)


def checkHyphen():
	"""The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes 
	separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage."""
	check = re.findall(r"-", fakeURL)
	if len(check)>0:
		testFeature.append(-1)
	else:
		testFeature.append(1)

def checkNoOfSubdomains():
	"""If the number of dots is greater than one, then the URL is classified "Suspicious" since it has one sub domain.
		However, if the dots are greater than two, it is classified "Phishing" since it will have multiple sub domains.
		Otherwise, if the URL has no sub domains, we will assign "Legitimate" to the feature.""" 
	names = correctURL.split('.')
	temp = re.findall(r'www/.', fakeURL)
	if len(temp) == 1:
		noOfSubdomains = len(names)-1
	else:
		noOfSubdomains = len(names)

	if noOfSubdomains == 1:
		testFeature.append(1)
	elif noOfSubdomains == 2:
		testFeature.append(0)
	else:
		testFeature.append(-1)


def usesHTTPS():
	"""The existence of HTTPS is very important in giving the impression of website legitimacy, but this is clearly 
	not enough. Certificate Authorities that are consistently listed among the top trustworthy names include: 
	“GeoTrust, GoDaddy, Network Solutions, Thawte, Comodo, Doster and VeriSign”. Furthermore, by testing out our 
	datasets, we find that the minimum age of a reputable certificate is two years."""

	flagHTTPS = 0
	flagCA = 0
	flagAge = 0
	ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'


	extract = tld.extract(correctURL)
	domain = extract.domain
	suffix = extract.suffix
	hostname = domain + '.' + suffix
	
	certificateAuthorities = ['GeoTrust', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign']
	temp = re.findall(r'https', correctURL)
	if len(temp) != 0:
		flagHTTPS = 1

	# To find the organization which issued the certificate.
	ctx = ssl.create_default_context()
	s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
	s.connect((hostname, 443))
	cert = s.getpeercert()
			
	subject = dict(x[0] for x in cert['subject'])
	issued_to = subject['commonName']
	issuer = dict(x[0] for x in cert['issuer'])
	issued_by = issuer['commonName']
			
	# if issued_by is in the list of trusted authorities, flag it 1
	if issued_by in certificateAuthorities:
		flagCA = 1
			
	port = '443'
	
	context = ssl.create_default_context()
	with socket.create_connection((hostname, port)) as sock:
	    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
	        data = json.dumps(ssock.getpeercert())
	        data = ssock.getpeercert()

	notAfter = datetime.datetime.strptime(data['notAfter'], ssl_date_fmt)
	notBefore = datetime.datetime.strptime(data['notBefore'], ssl_date_fmt)

	# Calculating the age
	age = notAfter - notBefore

	if(age.days>=365):
		flagAge = 1

	if flagAge and flagCA and flagHTTPS:
		testFeature.append(1)
	elif flagHTTPS == 1 and flagCA == 0:
		testFeature.apppend(0)
	else:
		testFeature.append(-1)

def checkDomainAge():
	"""Based on the fact that a phishing website lives for a short period of time, 
	we believe that trustworthy domains are regularly paid for several years in advance."""
	info = whois.whois(fakeURL)

	expirationDate = info.expiration_date 
	creationDate = info.creation_date

	if(creationDate == None or expirationDate == None):
		testFeature.append(-1)
	else:
		year = expirationDate.year-creationDate.year
		month = expirationDate.month-creationDate.month
		testFeature.append(1)

"""

	 	 #-----------------CHECK THIS-----------------------------
	This feature is useful in validating if a particular service (e.g. HTTP) is up or down on a specific server.
		In the aim of controlling intrusions, it is much better to merely open ports that you need. If all ports are 
		open, phishers can run almost any service they want and a result, user information is threatened

		FTTP (TCP): 111 = Connection refused
		SSH: 9 = File transfer protocol mismatch 
		Telnet (TCP): 9 = Bad file descriptor
		
		
		SMB (TCP): 9 = Bad file descriptor
		MSSQL (TCP): 9 = Bad file descriptor:
		ORACLE:
		MySql (TCP): 9 = Bad file descriptor:
		Remote Desktop:
	
	flag=0
	portList = [21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389]
	checkList = [111, 9, 9, 9, 9, 9, 9, 9, 9, 9]
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	

	for portNo in portList:
		result = sock.connect_ex(('127.0.0.1',portNo))
		print(result)
		openPortList
		if result == 0:
			# port no:80->HTTP
			# port no:443->HTTPS
			if portNo != 80 or portNo != 443:
				flag=1
				print("HTTP not open")
			else:
				flag=0
				break
		else:
			flag=1

		sock.close()

	if flag:
		testFeature.append(1)
	else:
		testFeature.append(-1)

checkPortStatus()
print(testFeature)
"""

def checkProtocolInSubdomain():
	"""The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users. For example,
		http://https-www-paypal-it-webapps-mpp-home.soft-hair.com."""
	print("inside protocolSubdomain")
	names = fakeURL.split('.')
	extract = tld.extract(fakeURL)
	subdomain = extract.subdomain
	temp = re.findall(r'http', fakeURL)
	if len(temp) == 1:
		testFeature.append(-1)
	else:
		testFeature.append(1)

#---------------------Abnormal based features-------------------
def checkAllTags():
	print("inside checkAllTags")
	c=0
	extract = tld.extract(correctURL)
	parentDomain = extract.domain
	links = []


	try:
		r = requests.get(correctURL)

		soup = BeautifulSoup(r.text, 'html.parser')
		for link in soup.findAll('a'):
			links.append(link.get('href'))

		for link in links:
			extract = tld.extract(link)
			domainName = extract.domain
			if(parentDomain != domainName):
				c=c+1

		if(c<22):
			testFeature.append(1)
		elif(c>=22 and c<=61):
			testFeature.append(0)
		else:
			testFeature.append(-1)


	except OSError:
		testFeature.append(-1)

def checkMailTo():
	print("inside mailto")
	flag=1
	emailList = []

	try:
		r = requests.get(correctURL)
	except OSError:
		emailList.append(1)
		flag=0


	if(flag):
		soup=BeautifulSoup(r.text,'html.parser')
		mailtos = soup.select('a[href^=mailto]')
		for i in mailtos:
			href=i['href']
			try:
				print("In try block")
				str1, str2 = href.split(':')
			except ValueError:
				print("In except block")
				break
			emailList.append(str2)


	if(len(emailList)):
		testFeature.append(-1)
	else:
		testFeature.append(1)


def checkAbnormalIdentity():
	print("inside abnormal Iden")
	"""This feature can be extracted from WHOIS database. For a legitimate website, identity is typically part of its URL.""" 
	flag=0
	info = whois.whois(correctURL)
	domainName = info.domain_name
	for name in domainName:
		if name in fakeURL:
			flag=1
		else:
			continue

	if(flag):
		testFeature.append(1)
	else:
		testFeature.append(-1)


"""def URLOfAnchor(): # fishy function. Check again
	r = requests.get(fakeURL)
	aTagList = ['JavaScript ::void(0)', '#', '#content', '#skip']
	soup = BeautifulSoup(r.text, 'html.parser')
	aTag = soup.findall('a', href=True)
	for tag in aTag:
		if tag in aTagList:
			c = c + 1

	if c < 31:
		print "Legit"
	elif c >= 31 and c <= 67:
		print "Suspicious"
	else:
		print "Phishing"




"""


#----------------------HTML and JS based features--------------
def checkWebsiteForwarding():
	print("inside websiteForwarding")
	flag=1
	try:
		response = requests.get(correctURL)
	except OSError:
		flag=0
		pass
	except UnboundLocalError:
		flag=0
		pass


	if(flag == 0):
		testFeature.append(-1)
	else:
		if(len(response.history)<=1):
			testFeature.append(1)
		elif(len(response.history)>=2 and len(response.history)<4):
			testFeature.append(0)


"""def iframeRedirection():
	soup = BeautifulSoup(html, "html.parser")
	listIframes = soup.find_all('iframe')
	if len(listIframes) != 0:
		print("Phishing")
	else:
		print("Legit")
iframeRedirection()"""

#-------------------------Domain based features------------------------------
def checkAgeOfDomain():
	print("insideAgeofDomain")
	info = whois.whois(correctURL)
	expirationDate = info.expiration_date 
	creationDate = info.creation_date
	year = expirationDate[0].year-creationDate[0].year
	month = expirationDate[1].month-creationDate[1].month
	if(year>0):
		testFeature.append(1)
	elif year==0:
		if month>=6:
			testFeature.append(1)
		else:
			testFeature.append(-1)

def checkDNSRecord():#-------------checkthis-------------------------------------
	print("inside DNS")
	ids = [
			'NONE','A','NS','MD','MF','CNAME','SOA','MB', 'MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB',
			'X25','ISDN','RT', 'NSAP', 'NSAP-PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','SRV','NAPTR','KX','CERT','A6',
			'DNAME','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY', 'DHCID','NSEC3','NSEC3PARAM','TLSA','HIP','CDS',
			'CDNSKEY','CSYNC','SPF','UNSPEC','EUI48','EUI64', 'TKEY','TSIG','IXFR','AXFR','MAILB','MAILA', 'ANY','URI','CAA','TA','DLV',
			]
	extract = tld.extract(fakeURL)
	domain = extract.domain
	suffix = extract.suffix
	domainName = domain + '.' + suffix

	c = 0
	for name in ids:
		try:
			records = dns.resolver.query(domainName, name)
			if records == None:
				c = c + 1
		except Exception as e:
			pass

	if(c == len(ids)):
		testFeature.append(-1)
	else:
		testFeature.append(1)

def websiteTraffic():
	print("inside webaite traffic")
	xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(correctURL)).read()
	result= xmltodict.parse(xml)
	 
	data = json.dumps(result).replace("@","")
	data_tojson = json.loads(data)
	url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
	alexa_rank= data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"]

	if int(alexa_rank)<100000:
		testFeature.append(1)
	elif int(alexa_rank)>100000:
		testFeature.append(0)
	else:
		testFeature.append(-1)

#------------------------remove paeRank column----------------------------------------
def checkPageRank(): 
	#-------------------some issue with page rank script----------------------
	# Can't really fix this. As of March 7th 2016, Google has removed the public PageRank metric completely. 
	# Google's John Mueller confirmed it via Twitter. Prior to this, Google had been allowing access to this data 
	# through APIs. Those APIs are all now deprecated and now no longer function.
	rank = pageRank.get_pagerank("https://www.udemy.com/topic/angular/")
	print(rank)
	if(float(rank)<0.2):
		print("Phishing")
	else:
		print("Legit")

havingIPAddress()
checkLengthOfURL()
checkTinyURL()
checkAtSymbol()
checkRedirects()
checkHyphen()
checkNoOfSubdomains()
usesHTTPS()
checkDomainAge()
checkProtocolInSubdomain()
checkAllTags()
checkMailTo()
checkAbnormalIdentity()
checkWebsiteForwarding()
checkAgeOfDomain()
checkDNSRecord()
checkAgeOfDomain()
websiteTraffic()

print(len(testFeature))
testLabel = 1 # label for the url provided