#python2.7.x compiled on Python 2.7.10 :: Anaconda 2.3.0 (64-bit)
#CveDetailsScaper.py
#A small python script used for scraping the CVE Details website for collating the following information
# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)

from bs4 import BeautifulSoup
import requests,pprint,sys,datetime,re
from argparse import ArgumentParser
import requests,pprint,csv,os,datetime,re,urllib2
import pandas as pd
from pandas import ExcelWriter
from pandas import ExcelFile
import calendar

cveIDNumber=[]
summaryText=[]
publishDate=[]
softwareType=[]
vendor=[]
product=[]
version=[]
cvssScore=[]
confidentialityImpact=[]
integrityImpact=[]
availibilityImpact=[]
accessComplexity=[]
authentication=[]
gainedAccess=[]
vulnType=[]
exploitAvailible=[]

confidentialityImpactTup=('Complete','None','Partial')
integrityImpactTup=('Complete','None','Partial')
availibilityImpactTup=('Complete','None','Partial')
accessComplexityTup=('Low','Medium','High') #Low means , accessible easily.
authenticationRequiredTup=('Not Required','Single System') #Single System implies that attacker requires a session.
accessLevelGainedTup=('None','Admin') #What is the access Level gained by exploiting this vulnerability

def parse_arguments(): # Function for parsing command line arguments
	parser = ArgumentParser(description='A small python script used for scraping the CVE Details website for collating the following information'+'\n'+'# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)')
	parser.add_argument('-smin',help='Minimum Severity Rating',default=7)
	parser.add_argument('-smax',help='Minimum Severity Rating',default=10)
	parser.add_argument('-m',help='Month in Number viz 1-12',default=datetime.date.today().month)
	parser.add_argument('-y',help='Year in YYYY',default=datetime.date.today().year)
	args=parser.parse_args()
	return args

def createFullUrl(smin,smax,year,month,page)	:
	url = "http://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page="+str(page)+"&cvssscoremin="+str(smin)+"&cvssscoremax="+str(smax)+"&year="+str(year)+"&month="+str(month)+"&order=3"
	return url

def getSoupHTML(url):
	response=requests.get(url)
	html=response.content
	soup = BeautifulSoup(html,"html.parser")
	#pprint.pprint(soup)
	return soup

def getCVEIds(soup,cveArray):
	table = soup.find('table',attrs={'class','searchresults'})
	for a in table.find_all('a',href=True):
		m = re.search("CVE-\d{4}-\d{4,7}",a['href'])
		if m:
			cveArray.append(m.group(0))
		
def getCVEPages(soup):
	cveIDPages=[]
	items=soup.find_all('div',class_="paging")
	for item in items:
		links=item.find_all('a')
		for link in links:
			cveIDPages.append("http://www.cvedetails.com/"+str(link['href']))
	
	return cveIDPages

def getCVEDetails(cveID):
	url="http://www.cvedetails.com/cve/"+cveID
	soup=getSoupHTML(url)
	
def getCVEDetails(cveid=''):
	cveUrl='http://www.cvedetails.com/cve/'+cveid+'/'
	response = requests.get(cveUrl)
	cveHtml=response.content
	soup = BeautifulSoup(cveHtml,"html.parser")
	if soup =='':
		return
	cveIDNumber.append(cveid)
	table = soup.find(id='vulnprodstable')
	cvssTable = soup.find(id='cvssscorestable')
	summarySoup=soup.find('div',class_="cvedetailssummary")
	summaryText.append(summarySoup.text.split("\n")[1])
	dateStr=summarySoup.text.split("\n")[3]
	publishDate.append(dateStr.split("\t")[1 ].split(":")[1])
	productData=[]
	for row in table.findAll('tr')[::-1]: #Get only the last row
		cols=row.findAll('td')
		for i in range(len(cols)):
			productData.append(cols[i].text.strip())	
	softwareType.append(productData[1])
	vendor.append(productData[2])
	product.append(productData[3])
	version.append(productData[4])
	cvssData=[]
	for row in cvssTable.findAll('tr'): #Get only the first row
		cols=row.findAll('td')
		for i in range(len(cols)):
			cvssData.append(cols[i].text.strip())			
	#pprint.pprint(cvssData)
	cvssScore.append(cvssData[0])
	ci=cvssData[1].split("\n")[0]
	confidentialityImpact.append(ci)
	ii=cvssData[2].split("\n")[0]
	integrityImpact.append(ii)
	ai=cvssData[3].split("\n")[0]
	availibilityImpact.append(ai)
	ac=cvssData[4].split("\n")[0]
	accessComplexity.append(ac)
	ar=cvssData[5].split("\n")[0]
	authentication.append(ar)
	al=cvssData[6].split("\n")[0]
	gainedAccess.append(al)
	vulnType.append(cvssData[7])
	
def writeToExcel(fileName=''):
	print "Writing to Excel File : "+fileName
	data = {'CVE ID Number': cveIDNumber, 'Summary Text': summaryText, 'Publish Date': publishDate, 'Software Type': softwareType, 'Vendor': vendor,'Product':product,'Version':version,'CVSS Score':cvssScore,'Confidentiality Impact':confidentialityImpact,'Integrity Impact':integrityImpact,'Availibility Impact':availibilityImpact,'Access Complexity':accessComplexity,'Authentication':authentication,'Gained Access':gainedAccess,'Vulnerability Type':vulnType}
	df = pd.DataFrame(data,columns=['CVE ID Number','Publish Date', 'Software Type','Vendor','Product','Version','CVSS Score','Confidentiality Impact','Integrity Impact','Availibility Impact','Access Complexity','Authentication','Gained Access','Vulnerability Type','Summary Text'])
	writer = ExcelWriter(fileName)
	df.to_excel(writer,'CVE Details',index=False)
	writer.save()
	print "Completed."
	
def main():
	args = parse_arguments()
	if args.m:
		month=args.m	
	if args.y:
		year=args.y
	if args.smin:
		smin=args.smin
	if args.smax:
		smax=args.smax
	
	fileName="Security_Advisory_"+calendar.month_name[month]+"_"+str(year)+".xlsx"
	fullUrl=createFullUrl(smin,smax,year,month,1)
	#print fullUrl
	soupObject=getSoupHTML(fullUrl)
	cvePagesArray=getCVEPages(soupObject)
	cveArray=[]
	for cvePage in cvePagesArray:
		#print cvePage
		soupObject=getSoupHTML(cvePage)
		getCVEIds(soupObject,cveArray)
	
	count=0
	for cve in cveArray:
		getCVEDetails(cve)
		count=count+1
		print "Getting Details for CVE ID: "+cve+". Completed "+str(count)+" Out of "+str(len(cveArray))
	
	writeToExcel(fileName)

if __name__ == '__main__':
    status = main()
    sys.exit(status)
