import tldextract as tld
import re
import whois # runs in python3
import dns.resolver
import seolib # for page ranking
import pageRank #paeRank algorithm(program) not written by me
import requests
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen, ssl, socket
from urllib.error import URLError, HTTPError
import json
from time import strptime

url = 'http://125.98.3.123/fake.html'


# ---------------Address bar based features------------------
def checkDomainName():
	extract = tld.extract(url)
	domainName = extract.domain
	c=0

	for character in domainName:
		if character=='.':
			c=c+1

	if c==3:
		print ("Phishing")

def checkLengthOfURL():
	if len(url)<54:
		print ("Legitimate")
	elif len(url)>=54 and len(url)<75:
		print ("Suspicious")
	else:
		print ("Phishing")


def checkTinyURL():
	extract = tld.extract(url)
	domain = extract.domain
	suffix = extract.suffix
	if domain=="bit" and suffix=="ly":
		print ("Phishing(uses tiny url)")

def checkAtSymbol():
	expr = "[@]"
	check = re.findall(r"@", url)
	if len(check)>0:
		print ("Phishing")
	else:
		print ("Legitimate")

def checkRedirects():
	expr = "[//]"
	p = re.compile(expr)
	iterator = p.finditer(expr)
	for match in iterator:
		lastIndex = match.end()

	if lastIndex > 7:
		print ("Phishing")
	else:
		print ("Legitimate")


def checkHyphen():
	check = re.findall(r"-", url)
	if len(check)>0:
		print ("Phishing")
	else:
		print ("Legitimate")


def checkNoOfSubdomains():
	names = url.split('.')
	temp = re.findall(r'www/.', url)
	if len(temp) == 1:
		noOfSubdomains = len(names)-1
	else:
		noOfSubdomains = len(names)

	if noOfSubdomains == 1:
		print ("Legit")
	elif noOfSubdomains == 2:
		print ("Suspicious")
	else:
		print ("Phishing")

def checkProtocolInSubdomain():
	names = url.split('.')
	extract = tld.extract(url)
	subdomain = extract.subdomain
	temp = re.findall(r'http', url)
	if len(temp) == 1:
		print ("Phishing")

def usesHTTPS():
	certificateAuthorities = ['GeoTrust', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign']
	temp = re.findall(r'https', url)
	if len(temp) !== 0:
		flagHTTPS = 1

	ctx = ssl.create_default_context()
	s = ctx.wrap_socket(socket.socket(), server_hostname=url)
	s.connect((url, 443))
	cert = s.getpeercert()

	subject = dict(x[0] for x in cert['subject'])
	issued_to = subject['commonName']
	issuer = dict(x[0] for x in cert['issuer'])
	issued_by = issuer['commonName']

	if issued_by in certificateAuthorities:
		flagCA = 1


	port = '443'

	hostname = url
	context = ssl.create_default_context()

	with socket.create_connection((hostname, port)) as sock:
	    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
	        print(ssock.version())
	        data = json.dumps(ssock.getpeercert())
	        # print(ssock.getpeercert())


	notBefore =  (data['notBefore'])
	yearB = notBefore[16:20]
	monthB = notBefore[4:6]
	dateB = notBefore[0:3]

	notAfter =  (data['notAfter'])
	yearA = notAfter[16:20]
	monthA = notAfter[4:6]
	dateA = notAfter[0:3]

	monthAname = strptime(monthA,'%b').tm_mon
	monthBname = strptime(monthB,'%b').tm_mon

	import datetime as dt

	nB = dt.dt(yearB, monthB, dateB)
	nA = dt.dt(yearA, monthA, dateA)

	age = nA-nB
	if(age.days>=365):
		flagAge = 1

	if flagAge && flagCA && flagHTTPS:
		print("Legit")
	elif flagHTTPS == 1 and flagCA == 0:
		print("Suspicious")
	else:
		print("Phishing")

def checkDomainAge():
	info = whois.whois(url)
	expirationDate = info.expiration_date 
	creationDate = info.creation_date
	year = expirationDate.year-creationDate.year
	month = expirationDate.month-creationDate.month
	if(year<=1):
		print ("Phishing")
		return year
	else:
		print("Legit")

def checkPortStatus():
	flag=0
	portList = [21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389]
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	

	for portNo in portList:
		result = sock.connect_ex(('127.0.0.1',portNo))
		if result == 0:
			if portNo != 80 or portNo != 443
		   		flag=1
		   	else: 
		   		flag=0
		   		break
		else:
		   flag=1
		sock.close()

	if flag:
		print("Legit")
	else:
		print("Phishing")

#-------------------------Domain based features------------------------------
def checkAgeOfDomain():
	info = whois.whois(url)
	expirationDate = info.expiration_date 
	creationDate = info.creation_date
	year = expirationDate.year-creationDate.year
	month = expirationDate.month-creationDate.month
	if(year>0):
		print ("Legit")
		return year
	elif year==0:
		if month>=6:
			print ("Legit")
		else:
			print ("Phishing")

def checkDNSRecord():
	ids = [
			'NONE','A','NS','MD','MF','CNAME','SOA','MB', 'MG','MR','NULL','WKS','PTR','HINFO','MINFO','MX','TXT','RP','AFSDB',
			'X25','ISDN','RT', 'NSAP', 'NSAP-PTR','SIG','KEY','PX','GPOS','AAAA','LOC','NXT','SRV','NAPTR','KX','CERT','A6',
			'DNAME','OPT','APL','DS','SSHFP','IPSECKEY','RRSIG','NSEC','DNSKEY', 'DHCID','NSEC3','NSEC3PARAM','TLSA','HIP','CDS',
			'CDNSKEY','CSYNC','SPF','UNSPEC','EUI48','EUI64', 'TKEY','TSIG','IXFR','AXFR','MAILB','MAILA', 'ANY','URI','CAA','TA','DLV',
			]
    extract = tld.extract(url)
    domainName = extract.domain
    for name in ids:
    	records=dns.resolver.query(domainName, name)
    	if records==None:
    		c=c+1

    if(c==len(ids)):
    	print("Phishing")
    else:
    	print("Legit")

def websiteTraffic():
	alexa_rank = seo.get_alexa(url)
	if alexa_rank<100000:
		print("Legit")
	elif alexa_rank>100000:
		print("Suspicious")
	else:
		print("Phishing")


def checkPageRank():
	rank = pageRank.get_pagerank(url)
	if(rank<0.2):
		print("Phishing")
	else:
		print("Legit")

#----------------------HTML and JS based features--------------
def checkWebsiteForwarding():
	response = requests.get(url)
	if(len(response.history<=1)):
		print("Legit")
	elif (len(response.history>=2 and len(response.history)<4)):
		print("Suspicious")
	else:
		print("Phishing")


def checkStatusBarCustomaization():
	r = requests.get(url)
	soup = BeautifulSoup(r.text, "html.parser")
	for tag in soup.findAll(onmouseover=True):
    	tag['onmouseover']
    	#function not complete. Check for status bar changes

def iframeRedirection():
	soup = BeautifulSoup(html, 'html.parser')
	listIframes = soup.find_all('iframe')
	if len(listIframes) != 0:
		print "Phishing"
	else:
		print "Legit"

#---------------------Abnormal based features-------------------

def checkAbnormalIdentity():
	flag=0
	info = whois.whois(url)
	domainName = info.domain_name
	for name in domainName:
		if name in url:
			flag=1
			break
		else:
			continue

		if(flag):x
			print("Legit")
		else:
			print("Phishing")

def checkMailTo():
	r = requests.get(url)
    soup=BeautifulSoup(r.text,'html.parser')
    mailtos = soup.select('a[href^=mailto]')
    for i in mailtos:
        href=i['href']
        try:
            str1, str2 = href.split(':')
        except ValueError:
            break
        
        emailList.append(str2)
    if(len(emailList)):# check for the length function
    	print("Phishing")
    else:
    	print("Legit")


def checkAllTags():
	c=0
	extract = tld.extract(url)
	parentDomain = extract.domain(extract)

	r = requests.get(url)
	soup = BeautifulSoup(r.text, 'html.parser')
	for link in soup.findAll('a'):
		links.append(link.get('href'))

	for link in links:
		extract = tld.extract(link)
		domainName = extract.domain
		if(parentDomain != domainName):
			c=c+1

	if(c<22):
		print("Legit")
	elif(c>=22 and c<=61):
		print("Suspicious")
	else:
		print("Phishing")



	

checkDomainName()
checkLengthOfURL()
checkTinyURL()
checkAtSymbol()
checkRedirects()
checkHyphen()
checkNoOfSubdomains()
checkProtocolInSubdomain()
checkDNSRecord()
checkAgeOfDomain()
websiteTraffic()
checkPageRank()