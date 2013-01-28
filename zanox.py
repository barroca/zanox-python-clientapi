import time, md5, random, hmac
from hashlib import sha1
from suds.client import Client
import base64
import json
import urllib2
import urllib
import sys

# Zanox authorization timestamp
def generateAuthorizationTimeStamp(tt=time.gmtime()):
  return _utf8_str(time.strftime("%Y-%m-%dT%H:%M:%S.000Z", tt))

# Zanox REST request timestamp
def generateRequestTimeStamp(tt=time.gmtime()):
	return _utf8_str(time.strftime("%a, %d %b %Y %H:%M:%S GMT", tt))

# Hexadecimal random nonce
def generateNonce(length=40):
	randomNumber = ''.join(str(random.randint(0, 9)) for i in range(length))
	m = md5.new(str(time.time()) + str(randomNumber))
	return _utf8_str(str(m.hexdigest()))

# check if date is on format like 2012-12-01
def validDate(date):
	ret = False 
	try:
		valid_date = time.strptime(date, '%Y-%m-%d')
	except ValueError:
		ret = False
	else:
		ret = True
	return ret

# check if is a valid interger
def validInteger(value):
	ret = True
	try:
		x = int(value)
	except ValueError:
		ret = False
	return ret

# check if dateType is trackingDate, modifiedDate, reviewStateChangedDate or clickDate
def validDateType(dateType):
	values = { "trackingDate", "modifiedDate", "reviewStateChangedDate", "clickDate" }
	ret = False
	if (dateType in values):
		ret = True
	return ret

# check if state is  "confirmed", "open", "approved" or "rejected"
def validState(state):
	values = { "confirmed", "open", "approved", "rejected" }  
	ret = False
	if (state in values):
		ret = True
	return ret

# converts a unicode string into utf8
def _utf8_str(s):
    """Convert unicode to utf-8."""
    if isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return str(s)

# contain a Session object with information		  
class Session(object):
	sessionKey = None;
	secretKey = None;
	sessionExpires = None;
	def __init__(self,sessionKey,secretKey,sessionExpires):
		self.sessionKey = sessionKey;
		self.secretKey = secretKey;
		self.sessionExpires = sessionExpires;

# contains the information of Zanox connection
class Zanox(object):
	connectId = None;
	secretKey = None;
	publicKey = None;
	applicationId = None;
	session = None;

	
	def __init__(self,connectId,secretKey,publicKey,applicationId):
		self.connectId = _utf8_str(connectId)
		self.secretKey = _utf8_str(secretKey)
		self.publicKey = _utf8_str(publicKey)
		self.aplicationId = _utf8_str(applicationId)

	def createRestSign(self,service,method,nonce,ts,secretKey):
		string2sign = _utf8_str(service) + _utf8_str(method)+ ts + nonce
		hashed = hmac.new(secretKey, _utf8_str(string2sign), sha1)
		encoded = base64.b64encode(hashed.digest())
		return str(encoded)

	def createSoapSign(self,service,method,nonce,ts,secretKey):
		string2sign = _utf8_str(service).lower() + _utf8_str(method).lower()+ ts + nonce
		hashed = hmac.new(secretKey, _utf8_str(string2sign), sha1)
		encoded = base64.b64encode(hashed.digest())
		return str(encoded)
	


	def getSession(self,authKey):
		ts = generateAuthorizationTimeStamp()
		nonce = generateNonce()
		encoded = self.createSoapSign("connectService","getSession",nonce,ts,self.secretKey)
		url = "https://auth.zanox.com/wsdl/"
		apiClient = Client(url)
		try:
			result = apiClient.service.getSession(authToken=_utf8_str(authKey),publicKey=self.publicKey,signature=encoded,nonce=nonce,timestamp=ts)
		except Exception as e:
			print "Fail: "+str(e)
			raise
		self.session = Session(str(result.sessionKey), str(result.secretKey), str(result.sessionExpires))
		return result

			


	def fillParametersForGetSalesAndGetLeadsRest(self,dateType,program,adspace,state,items,page):
		urlToOpen = ""
		if (validDateType(dateType)):
			urlToOpen += "&dateType="+dateType
		if (validInteger(items)):
			urlToOpen += "&items="+str(items)
		if (validInteger(page)):
			urlToOpen += "&page="+str(page)
		if (validState(state)):
			urlToOpen += "&state="+state
		if (validInteger(program)):
			urlToOpen += "&program="+str(program)
		if (validInteger(adspace)):
			urlToOpen += "&adspace="+str(adspace)
		return urlToOpen


	def fillAuthParameters(self,connectId,date,signature,nonce):
		urlToOpen = ""
		if (connectId != ""):
			urlToOpen+= "?connectid="+connectId
		if (date != ""):
			urlToOpen += "&date="+urllib.quote(date)
		if (nonce != ""):
			urlToOpen += "&nonce="+nonce
		if (signature != ""):
			urlToOpen += "&signature="+signature
		return urlToOpen

	def doHttpRequest(self,urlToOpen):
		req = urllib2.Request(url=urlToOpen)
		result=""
		try:
			f = urllib2.urlopen(req)
			result = f.read()
		except urllib2.HTTPError as e:
			if (e.code == 403):
				print "Authorization Error"
				result = ""
			if (e.code == 404):
				print "Problem with url, please check parameters" 
				result = ""
			else:
				result = "Exception: {0}, {1}, {2} ".format(e.code,e.message,urlToOpen)
			print "Exception: {0}, {1}, {2} ".format(e.code,e.message,urlToOpen)
		except Exception as e:
			result = "Exception: "+e.__class__.__name__
		return result

	def createRestUrl(self,resource):
		url = "http://api.zanox.com/json/2011-03-01"
		action = "GET"
		urlToOpen = url+resource
		urlToOpen +=self.createUrlAuthorizationParameters(resource,action)
		return urlToOpen


	def createUrlAuthorizationParameters(self,resource,action):
		tt=time.gmtime()
		headerDate = generateRequestTimeStamp(tt)
		nonce = generateNonce()
		encoded = self.createRestSign(action,resource,nonce,headerDate,self.secretKey)
		urlToOpen = self.fillAuthParameters(self.connectId,headerDate,encoded,nonce)
		return urlToOpen

	def getSales(self,date="",dateType="",program="",adspace="",state="",items=-1,page=-1):
		if (not validDate(date)):
			print('Invalid date!')
			return ""
		resource = "/reports/sales/date/"+date
		urlToOpen = self.createRestUrl(resource)
		urlToOpen+=self.fillParametersForGetSalesAndGetLeadsRest(dateType, program, adspace, state, items, page)
		return self.doHttpRequest(urlToOpen)
		
	def getLeads(self,date="",dateType="",program="",adspace="",state="",items=-1,page=-1):
		if (not validDate(date)):
			print('Invalid date!')
			return ""
		resource = "/reports/leads/date/"+date
		urlToOpen = self.createRestUrl(resource)
		urlToOpen +=self.fillParametersForGetSalesAndGetLeadsRest(dateType, program, adspace, state, items, page)
		return self.doHttpRequest(urlToOpen)

	def getSale(self,saleId=""):
		if (saleId == ""):
			return ""
		resource = "/reports/sales/sale/"+saleId
		urlToOpen = self.createRestUrl(resource)
		return self.doHttpRequest(urlToOpen)

	def getLead(self,leadId=""):
		if (leadId == ""):
			return ""
		resource = "/reports/leads/lead/"+leadId
		urlToOpen = self.createRestUrl(resource)
		return self.doHttpRequest(urlToOpen)
