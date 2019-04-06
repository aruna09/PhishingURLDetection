import tldextract as tld
import re


url = 'http://125.98.3.123/fake.html'

"""
Rule: IF Domain has IP address ->Phishing
		 		Otherwise      -> Legitimate
"""
def checkDomainName():
	extract = tld.extract(url)
	domainName = extract.domain
	c=0

	for character in domainName:
		if character=='.':
			c=c+1

	if c==3:
		print "Phishing"


"""
Rule: IF len(url)<54         -> Legitimate
	  else if 54<len(url)<75 -> Suspicious
	  else                      Phishing
"""
def checkLengthOfURL():
	if len(url)<54:
		print "Legitimate"
	elif len(url)>=54 and len(url)<75:
		print "Suspicious"
	else:
		print "Phishing"


def checkTinyURL():
	extract = tld.extract(url)
	domain = extract.domain
	suffix = extract.suffix
	if domain=="bit" and suffix=="ly":
		print "Phishing(uses tiny url)"

def checkAtSymbol():
	expr = "[@]"
	check = re.findall(r"@", url)
	if len(check)>0:
		print "Phishing"
	else:
		print "Legitimate"

def checkRedirects():
	expr = "[//]"
	p = re.compile(expr)
	iterator = p.finditer(expr)
	for match in iterator:
		lastIndex = match.end()

	if lastIndex > 7:
		print "Phishing"
	else:
		print "Legitimate"


def checkHyphen():
	check = re.findall(r"-", url)
	if len(check)>0:
		print "Phishing"
	else:
		print "Legitimate"


def checkNoOfSubdomains():
	names = url.split('.')
	temp = re.findall(r'www/.', url)
	if len(temp) == 1:
		noOfSubdomains = len(names)-1
	else:
		noOfSubdomains = len(names)

	if noOfSubdomains == 1:
		print "Legit"
	elif noOfSubdomains == 2:
		print "Suspicious"
	else:
		print "Phishing"

def checkProtocolInSubdomain():
	names = url.split('.')
	extract = tld.extract(url)
	subdomain = extract.subdomain
	temp = re.findall(r'https/.', url)
	if len(temp) == 1:
		print "Phishing"


checkDomainName()
checkLengthOfURL()
checkTinyURL()
checkAtSymbol()
checkRedirects()
checkHyphen()
checkNoOfSubdomains()