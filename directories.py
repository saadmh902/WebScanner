from colorama import Fore, Back, Style,init
import requests
import time
from datetime import date
import datetime
from urllib.parse import urlparse
import webbrowser
import os
#from requests_html import HTMLSession
from bs4 import BeautifulSoup
import socket
import paramiko
import ftplib
from lxml.etree import ParserError
import random
import json

#####################################################################
#																																		#
#	Written by Saad M 																								#
#	Please excuse the messy code this is my first proper project			#
#						👉👈																										#
#																																		#
#####################################################################

# DISCLAIMER : Only use this tool for servers you have explicit permission to test on!
# I am not liable for any damage you cause!

def cuteTable(*args):#Usage cuteTable(("Text",4),("sample,6)) (Text to input and approx max char length)  
	#print ("{:<2} {:<3}{:<30} {:<9} {:<2}".format(row1,row2,row3,row4,row5))
  string = []
  newformat = ""
  for line in args:
    string.append(line[0])
    newformat +=("{:<"+str(line[1])+"}")

  print(newformat.format(*string))



def generateUserAgent():
	f = open("payload/user_agents.txt", "r")
	data = json.load(f)
	randomBrowser = random.choice(["chrome","opera","firefox","internetexplorer","safari"])
	browser = data["browsers"][randomBrowser][random.randint(0,50)]
	return browser

def DoesFormActionExist(item,goodItems):#Avoid duplicate form actions
	result = False
	for line in goodItems:
		if(item == line[0] and line[2] == "FORM ACTION"):
			result = True
			break
	return result

def getErrorPage(url,cookies):#Use this function to check against all further requests to make sure <200> pages aren't actually <404>
	randomChars = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"]
	randomChars += ["0","1","2","3","4","5","6","7","8","9"]
	i = 0
	randomString = ""
	while(i < 50):
		if(random.choice([0,1])==0):
			randomString += random.choice(randomChars)
		else:
			randomString+=random.choice(randomChars).lower()
		i+=1
	#randomString += ".php"
	print("Fetching 404 page with GET:" + randomString)
	r = requests.get(url + randomString,cookies=cookies)
	return r.content


def setColor(text,color):
	if(color == "green"):
		return Fore.GREEN + text + Style.RESET_ALL
	elif(color == "red"):
		return Fore.RED + text + Style.RESET_ALL
	elif(color == "yellow"):
		return Fore.YELLOW + text + Style.RESET_ALL

def alertMessage():
	return "[" + setColor("ALERT","green") + "]: "
def warningMessage():
	return "[" + setColor("WARNING","yellow") + "]: "

def checkForFTP(url,search_level):#Check if FTP connections can be made
	#if ("000webhost.com" in url):
	#	url = url.replace("000webhost.com","000webhostapp.com",1)
	ip = urlparse(url)
	ip ='{uri.netloc}'.format(uri=ip)
	print("Attempting to make an FTP connection to " + ip)
	loginDictionary = []
	info = ("root","root")
	loginDictionary.append(info)
	info = ("admin","admin")
	loginDictionary.append(info)
	info = ("adminstrator","adminstrator")
	loginDictionary.append(info)

	noauth_connection = []
	auth_connection = []

	loginIPs = [ip]
	if(search_level == 1):
		ftppayload = "payload/common_ftp.txt"
		with open(ftppayload) as file:
			lines = file.read().splitlines()
			for line in lines:
				line = line.split(":")
				try:
					info = (line[0],line[1])
				except:continue
				loginDictionary.append(info)

		loginIPs = [ip,"ftp."+ip,"files."+ip]

	attempts = 0
	for loginIP in loginIPs:#Make output pretty
		print("Trying IP: " + loginIP+"\t\t\t\t\t\t\t\t\t")
		for line in loginDictionary:
			attempts+=1
			try:
				print("\tConnecting with "+loginIP + " @ (" + line[0] + ":" +line[1] + ")\t ("+str(attempts)+"/"+str(len(loginDictionary) * len(loginIPs))+")\t\t", end="\r")
				session = ftplib.FTP(loginIP,line[0],line[1])
				print(session,end="\r")
				print("FTP Access granted using user '" + line[0] + "' and pass '"+line[1]+"'\t\t\t")
				session.close()
				auth_connection.append("True")
				continue
				#return True
			except socket.gaierror:
				print("Could not connect to FTP server ("+str(attempts)+")\t\t",end="\r")
			except ftplib.error_perm:
				#print("Connection made but FTP Auth Failed! "+loginIP + " @ (" + line[0] + ":" +line[1] + ")\t\t\t\t", end="\r")
				noauth_connection.append("True")
				#session.close()
				continue
				#return True
			except TimeoutError:
				print("FTP Timeout! ("+str(attempts)+")\t\t\t\t\t\t\t",end="\r")
			except ConnectionRefusedError:
				print("FTP Connection Refused ("+str(attempts)+str(len(loginDictionary))+")\t\t\t\t\t\t\t",end="\r")
			except Exception as e:
				print (Exception + e)


	if("True" in auth_connection):
		print(alertMessage()+"FTP Connection established and auth made\t")
		if(len(auth_connection > 2)):
			print(warningMessage() + "Multiple Auth Connections, be careful of false positives.")
		return True
	elif("True" in  noauth_connection):
		print(alertMessage()+"FTP Connection Established but no auth made\t")
		return True
	else:
		print("["+setColor("FAILURE","red")+"] FTP Connection Failed!\t\t\t\t")
		return False
	#To do  add to report


def checkForSSH(url):#Check if SSh connections can be made
	ip = urlparse(url)
	ip ='{uri.netloc}'.format(uri=ip)

	print("Attempting to make an SSH connection to " + ip)
	loginDictionary = []
	info = ("root","root")
	loginDictionary.append(info)
	info = ("admin","admin")
	loginDictionary.append(info)
	info = ("adminstrator","adminstrator")
	loginDictionary.append(info)
	for line in loginDictionary:
		try:
			host = "localhost"
			username = line[0]
			password = line[1]
			print("Auth as "+username+":"+password,end="\r")
			#username = "root"
			#password = "root"

			client = paramiko.client.SSHClient()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			client.connect(host, username=username, password=password)
			_stdin, _stdout,_stderr = client.exec_command("ls -l")
			print(stdout.read().decode())
			print("It looks like SSH access was made!")
			print(alertMessage()+"SSH Access granted using user '" + line[0] + "' and pass '"+line[1]+"'")
			#To do Add user and pass to report.html
			input()
			client.close()
			return True
		except socket.gaierror:
			print("SSH server not valid.")
			#input()
			#break
		except paramiko.ssh_exception.BadAuthenticationType:
			print(alertMessage()+"Connection to SSH made!\nCan't auth, requires ssh key.")
			#input()
			return True
			#break
			continue
		except paramiko.ssh_exception.NoValidConnectionsError:
			continue
			#print("Could not make an SSH connection")
			#break
			#input()
			#break
	print("["+setColor("FAILURE","red")+"] SSH Connection Failed!\t\t\t\t\t")
	return False




def checkForPorts(url,portsOpen):#Check if the target has open ports
	def openPort(ip,port,sock,portsOpen):#Open one specific port
		result = sock.connect_ex((ip,port))
		if result == 0:
		   print (str(port)+" is open")
		   portsOpen.append(port)
		else:
		   #print(result)
		   print (str(port)+" is not open")

	ip = urlparse(url)
	ip ='{uri.netloc}'.format(uri=ip)#Convert URL to IP
	print("Ports Available on: " + ip)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	openPort(ip,80,sock,portsOpen)#HTTP
	openPort(ip,21,sock,portsOpen)#FTP
	openPort(ip,22,sock,portsOpen)#SSH
	openPort(ip,23,sock,portsOpen)#Telnet
	openPort(ip,25,sock,portsOpen)#SMTP
	openPort(ip,53,sock,portsOpen)#DNS
	openPort(ip,443,sock,portsOpen)#http secure
	openPort(ip,3306,sock,portsOpen)#sql
	sock.close()





def DoesServiceExist(service,servicesFound):#If the service exists return true or false
	result = False

	for count,line in enumerate(servicesFound):
		if(line[0] == service):
			#print(line[0] + " already exists\t\t\t")
			#input()
			result = True
			return result
	return False
def getServices(url,response,goodItems,cookies,serverInfo,servicesFound):
	def addService(serviceName,dictionary,servicesFound):
		#service = "WordPress"
		#dictionary = ["wp-admin","wp-content","wpo-plugins-tables-list","wordpress"]#WordPress
		for line in dictionary:
			#print(line + " in " + url)
			if(line in url):
				information = (serviceName,url)
				if(DoesServiceExist(serviceName,servicesFound) == False): #Only add service if it doesn't already exist, to avoid duplicates!
					servicesFound.append(information)#WordPress service was found add it to list
					#print("Added "+str(information) + " to list!\n")
					#input()
				

	

	#addService("Name To Be Displayed", [Dictionary to be checked], array to check)
	addService("WordPress",["wp-admin","wp-content","wpo-plugins-tables-list","wordpress"],servicesFound)
	addService("cPanel",["cpanel"],servicesFound)
	addService("phpMyAdmin",["phpmyadmin"],servicesFound)


def getWebServerInfo(url,response,goodItems,cookies,serverInfo):#This is used on nginx/apache pages that divulge server information
	#print("Looking for server info...",end="\r")
	#r = requests.get(url)
	parser = BeautifulSoup(response.content, 'html.parser')#apache
	for line in parser.find_all("address"):
		print(alertMessage()+"Retrieved Server Information: ("+line.decode_contents() + ") this information was found on "+url)
		information = (line.decode_contents(),"Server Info: ")
		serverInfo.append(information)
	for line in parser.find_all("center"):#nginx
		if "nginx" in line.decode_contents():
			information = (line.decode_contents(),"Server Info: ")
			serverInfo.append(information)	
			print("[ALERT]: Retrieved Server Information: ("+line.decode_contents() + ") this information was found on "+url)	

def scanRobots(url,goodItems,cookies,headers):
	print("Scanning robots file for new items\t\t\t\t\t")
	blacklist = ["User-agent","Crawl-delay"]#Ignore populating from this list
	response = requests.get(url + "robots.txt",cookies=cookies,headers=headers)
	robotsFound = []
	for line in response.iter_lines(): #Use instead of text to get each line from .txt
		try:
			line = str(line)
			split = line.split(": ",1)
			item = split[1]
			prefix = split[0].replace("b'","",1)
			if(prefix in blacklist):#e.g. if User-agent: then pass
				continue
			if(item[0] == "/"):
				item = item.replace("/","",1) # /folder => folder
			if(item[-1] == "'"):
				item = item.replace("'", "", (item.count('')-1)) # sitemap.xml' => sitemap
			#print(item + " found",end="\r")
			information = (item,"ROBOTS","OTHER")
			goodItems.append(information)
		except:continue

	print("Scanning robots completed! ({} URLs found)\t\t\t\t\t\t".format(len(robotsFound)))

def saveAndShowItems(url,goodItems,serverInfo,servicesFound,portsOpen,timeElapsed): #Show successful items and save data to report

	def sortFunc(e): #Sort the list by the [CODE] ascending order (typically green 200, yellow 400, and blue robots)
		return str(e[1])

	goodItems.sort(key=sortFunc,reverse=False)
	date = datetime.datetime.now()
	newFileDate = str(date.year) + "-" + str(date.month)+ "-" +str(date.day) + "-" + str(date.hour)+str(date.minute)+str(date.second)

	fileUrl = urlparse(url)
	fileUrl ='{uri.netloc}'.format(uri=fileUrl)
	newFile =  fileUrl + "_" + newFileDate + ".html"
	print("Writing report to disk...")
	display_server_info = "<b>Server Software: </b><span>Inconclusive.</span>" 
	if(len(serverInfo) > 0):#Display server info apache/nginx etc
		display_server_info = "<b>Server Information: </b><span>"+serverInfo[0][0]+"</span><br>"
	display_services = """
	<b>No Services were found</b><br>
	"""
	if(input("Would you like to check for SSH/FTP connections? (Y/N): ").lower() == "y"):
	#print("Would you like to check for SSH/FTP connections? (Y/N)")
		if(checkForSSH(url) == True):
			information = ("SSH","Active")
			servicesFound.append(information)
		else:
			information = ("SSH","No Connection")
			servicesFound.append(information)
		if(checkForFTP(url,0) == True):
			information = ("FTP","Active")
			servicesFound.append(information)
		else:
			information = ("FTP","No Connection")
			servicesFound.append(information)
	else:
		print("Skipped FTP/SSH checks")
		#information = ("SSH","Skipped Check")
		#information2 = "FTP","Skipped Check"
		#servicesFound.append(information)
		#servicesFound.append(information2)
	#ports
	checkForPorts(url,portsOpen)
	if(len(servicesFound) > 0): #Display services, wordpress cpanel roundcube etc
		display_services = "<table style='margin-top:10px;'><tr><th>Services Found</th><th>-</th></tr>"
		for count,line in enumerate(servicesFound):
			display_services+= "<tr><td>" + line[0] +"</td><td>"+line[1] + "</td></tr>"
		display_services += "</table>"
			
	with open("exports/"+newFile, "w") as myfile:


		myfile.write('''
			<style>.orange { color:orange; } .green { color:green } .blue { color:blue } .grey { color:grey } html { font-family:Arial; } </style>
			<h1>Scan Report: <a href="''' +url + '">'+url+'</a> @ ' + newFileDate+'''</h1>
			'''+display_server_info+'''
			'''+display_services+'''
			<table><tr><th>Item</th><th>Code</th><th>Type</th></tr><tr>''')
		myfile.write("<b>Ports Available:</b>")
		for line in portsOpen:
			myfile.write("<p>Port: "+str(line)+"</p>")
		end = time.time()
		endTime = end - timeElapsed
		endTime = str(round(endTime, 2))
		print("Scan on "+url+ " took "+endTime+" seconds")
		myfile.write("<b>Total Scan Time: </b><span>"+str(endTime)+" seconds</span><br>")
		myfile.write("<b>Total Entries Found: </b><span>"+ str(len(goodItems))+"</span>")
		for list in goodItems:#Iterate through good items, add them to report and display eeach item
			if(len(str(list[0])) > 74):#If item is too long trim it down for display in terminal
				trimmed = str(list[0])
				trimmed = trimmed[0:70]
				trimmed = str(trimmed + "...")
				printcode = str(list[1])
				cuteTable((trimmed,75),(printcode,10))
				#print(str(trimmed) + "\t<"+str(list[1])+">")

			else:

				printinfo = str(list[0])
				printcode = str(list[1])
				cuteTable((printinfo,75),(printcode,10))

			if("External" in list[2]):
				href = str(list[0])
			else:
				href = url + str(list[0]) #Absolute path

			tdClass = ""#Set CSS of items based of [1] and [2] values
			if((list[1] == 200) and list[2] != "REDIRECT"):
				tdClass = "green"
			elif(list[1] == 403 and list[2] != "REDIRECT"):
				tdClass = "orange"
			elif(list[1] == "ROBOTS"):
				tdClass = "blue"
			elif(list[2] == "REDIRECT"):
				tdClass = "grey"
			if(list[2] == "Internal HyperLink"):
				href = str(list[0]) #http://localhost/ instead of http://localhost/localhost/index.php
			myfile.write("<tr><td><a class='"+tdClass+"' href='"+href +"'> " + str(list[0]) + "</a></td><td>" + str(list[1]) + "</td><td>" + str(list[2]) + "</td></tr>")
		myfile.write("</table>")

		print("Services found:")#Iterate throguh servicesFound and display them
		for list in servicesFound:
			print(str(list[0]))
		

		#Ports


		def endLine(newFile):
			equalsRange = len(newFile)
			equalLine = ""
			for line in range(0,equalsRange+22):#+22 because everything before + newFile equals 22 chars
				equalLine += "="
			print(setColor("+"+equalLine+"+","yellow"))
		




		myfile.close()

		endLine(newFile)
		
		print("Data saved to exports/" + newFile)

		endLine(newFile)
		while(True):
			openReport = input("Open report? (Y/N): ")
			if(openReport.lower() == "y"):
				currentDir = os.path.abspath(os.getcwd())
				currentDir = currentDir.replace("\\","/")
				currentDir += "/exports/"
				openfile = 'file://'+currentDir+newFile
				#print(openfile)
				webbrowser.open(openfile, new=2)
				print("Opening Report.\n\n\n")
				break
			elif(openReport.lower() == "n"):
				print("Skipped report.")
				break
			else:
				print("Please choose Y or N.")
		input("Press ENTER to continue.")
		print("\n\n\n\n")
def lookForLinks(baseurl,url,response,cookie,goodItems,headers): #This function opens successful files and looks for links
	soup = BeautifulSoup(response.content,"lxml")
	links = soup.find_all("a")
	links.extend(soup.find_all("link"))
	links.extend(soup.find_all("script"))
	links.extend(soup.find_all("meta"))
	links.extend(soup.find_all("img"))
	links.extend(soup.find_all("li"))
	links.extend(soup.find_all("base"))
	links.extend(soup.find_all("area"))

	#FETCH LINKS
	def addElementAttribute(line,goodItems,url,attribute): #addElementAttribute(<ELEMENT>,goodItems,url,href/src)
		if(line.get(attribute) != None):
			line = line.get(attribute)
			my_hostname = urlparse(url)
			my_hostname ='{uri.netloc}'.format(uri=my_hostname)
			check_hostname = urlparse(line)
			check_hostname ='{uri.netloc}'.format(uri=check_hostname)
			if((my_hostname in check_hostname) or check_hostname == ""):
			#if(my_hostname in check_hostname or my_hostname == ""):#if line hosttname and URL hostname are same then append, e.g. http://localhost/index.php => http://localhost/post.php = Good http
				#print("'"+line+"' hyperlink found\t\t\t\t\t\t",end="\r")
				information = (baseurl+line,"N/A","Internal HyperLink")
				#Check if information already exists in goodItems
				doesFileExist = False
				for counter,item in enumerate(goodItems):
					if(goodItems[counter][0] == information[0]):
						#print("Item Already Exists" + goodItems[counter][0])
						doesFileExist = True
						break
				if(doesFileExist == False):
					goodItems.append(information)
					print("Grabbing all links from: '"+url+"'\t\t\t\t\t", end="\r")
			else:
				information = (line,"N/A","External HyperLink")
				doesFileExist = False
				for counter,item in enumerate(goodItems):
					if(goodItems[counter][0] == information[0]):
						#print("Item Already Exists" + goodItems[counter][0])
						doesFileExist = True
						break
				if(doesFileExist == False):
					goodItems.append(information)
					print("Grabbing all links from: '"+url+"'\t\t\t\t\t", end="\r")
	for line in links: #Fetches hrefs
		addElementAttribute(line,goodItems,url,"src")
		addElementAttribute(line,goodItems,url,"href")

	#FETCH ACTIONS
	r = requests.get(url,headers=headers)#Fetches actions
	parser = BeautifulSoup(r.content, 'html.parser')#Get form actions
	forms = [f.get('action') for f in parser.find_all('form')]
	for actionLine in forms:
		if actionLine == None:
			actionLine = "No URL"
		if(DoesFormActionExist(actionLine,goodItems) == False):
			print("'"+actionLine+"' <form> action found\t",end="\r")
			information = (actionLine,"200","FORM ACTION")
			goodItems.append(information)


	

def scanDirectories(url,cookie,search_level):
	#start cookies
	if(cookie == "n"):
		cookies = {'': ''}
	else:
		cookies = {'PHPSESSID': ''}#Change to get from a cookiefile
	session = requests.Session()
	print(url)
	response = session.get(url)
	retrievedCookie = session.cookies.get_dict()
	cookies = retrievedCookie
	print(str(retrievedCookie) + " retrieved as cookie.")

	#end cookies


	ua = generateUserAgent()
	print("Generated Random User Agent: "+ ua)
	headers = {
    'User-Agent': ua,
    #'key': 'value' to populate later
	}

	goodItems = []
	serverInfo = []
	servicesFound = []
	portsOpen = []

	errorPage = getErrorPage(url,cookies)

	class commonFiles(): #Class for all files to search through

		# Each file will be checked against each extension
		# E.g. index => index.html index.php index.pl index.txt etc
		files = ["index","cgi"] #Typical index files
		files.extend([".htaccess",".htpasswd","robots"]) #Apache files
		files.extend(["404","405","503","504"]) #Error pages
		files.extend(["style","stylesheet","styles","css"]) #CSS 
		files.extend(["footer","header"])#page structure files
		files.extend(["login","register","passwords","pass","passes","passwd","passwds","log-in","log","logs","signup","sign-up","logout","log-out"])#Auth files
		files.extend(["members","members_area","member","user","profile","users","members_list"]) #Profile files
		files.extend(["view","product"])#product
		files.extend(["about","about_us","aboutus"]) #About us pages
		files.extend(["contactus","contact_us"]) #contact us pages
		files.extend(["gallery","photo","imag"]) #Gallerys
		files.extend(["js","java","javascript"])#JavaScript files/directories

		files.extend(["home","notice",]) #General files
		#files.extend(["oldindex","test","testadf","testasdf","testasf","t"]) #Files sometimes left behind devs
		#files.extend(["dev","development","testing"]) # more development files
		#files.extend(["wp-admin","phpmyadmin","cpanel"])

		#Extensions to be appended to each files[]
		extensions = [".html",".php",".htm",".shtml",".txt",".ico",".css",".js",""]
		deepExtensions = [".pl",".exe",".pdf",".png",".jpg",".jpeg",".zip",".rar",".asp",".aspx"]

		#Directories to be checked against without an extension
		directories =  ["admin","admincp","cpanel","phpmyadmin","wp-admin","login","logout","settings","img","images","image","assets","register","dashboard","roundcube","downloads","download","dload","private","backup","backups","back-up"] #DIRECTORIES
		directories.extend(["tools","pipermail","controlpanel","mailman","whm","cgi-sys","cgi-bin","fonts","font"])
		wordpress = ["wp-content/uploads/wpo-plugins-tables-list.json"] #wordpress files


	print("Beginning scan of " + url)
	start = time.time()
	try:
		baseresponse = requests.get(url,cookies,headers=headers)
	except requests.exceptions.InvalidSchema:
		print("Failed to connect, URL invalid")
		return
	except requests.exceptions.ConnectionError:
		print("Couldnt resolve domain")
		return

	if(baseresponse.status_code == 200 or baseresponse.status_code == 406 or baseresponse.status_code == 403):
		print(alertMessage()+"Success! Connected to "+ url)

		#print(baseresponse.content)
		#Begin Scanning 
		#Scan common files

		timerDelay = 0.00
		commonFiles = commonFiles()

		#Add dirbuster directories to object to enlarge scan

		if(search_level == 1):
			with open("payload/dirbuster.txt") as file:
				lines = file.read().splitlines()
				for line in lines:
					commonFiles.directories.extend([line])

		filesFound = []
		for mainCount,line in enumerate(commonFiles.files):
			for count,extensions in enumerate(commonFiles.extensions):

				page = line + extensions
				print("Checking for file: '" + page + "' (" + str(mainCount) + "/" + str((len(commonFiles.files) * len(commonFiles.extensions))+ 1) +")\t\t\t\t\t\t" ,end='\r')
				time.sleep(timerDelay)
				try:
					response = requests.get(url + page,cookies,headers=headers,cookies=retrievedCookie)
					if((response.status_code >= 100 and response.status_code <= 399) or response.status_code == 403 or response.status_code == 406): ##If the file exists then save it
						code = response.status_code
						if(response.history == []):
							itemType = "File"
							information = (page,code,itemType)

						else:
							#print(response.history)
							itemType = "REDIRECT"
							information = (page,code,itemType)
						if(len(serverInfo) == 0 and response.content != errorPage):#If serverinfo wasnt already grabbed, collect info
							getWebServerInfo(url+page,response,goodItems,cookies,serverInfo)
						if(code == 200):#The page is good, now check it for any other links
							lookForLinks(url,url+page,response,cookie,goodItems,headers)
						if(page == "robots.txt" and response.content != errorPage): ##If robots.txt is good then scan the robots doc
							scanRobots(url,goodItems,cookies,headers)
						if(response.content != errorPage): #If the request doesnt match the 404 page then continue 
							goodItems.append(information)
							filesFound.append(1)
							getServices(page,response,goodItems,cookies,serverInfo,servicesFound)#Check if this page give service info e.g. phpmyadmin wordpress etc
						else:
							print("404",end="\r")
							#input()
						
				except ParserError:
					print("Request was empty ignoring...\t\t\t\t\t\t\t")
				except TypeError as e:
					print(e)
				except Exception as e:
					###FIX THIS###
					timerDelay += 1
					print("Failed to connect, increasing time delay by to " + str(timerDelay) + " seconds")
					print(e)
					code = "Error"
					itemType = "File"
					information = (page,code,itemType)
					goodItems.append(information)
					continue

		print("Scanning Files Completed! ({} files)\t\t\t\t\t\t".format(len(filesFound)))

		#Scan common directories
		directoriesFound = []
		for count,line in enumerate(commonFiles.directories):
			print("Checking for directory: '" + line + "' (" + str(count) + "/" + str(len(commonFiles.directories) + 1) +")\t\t\t\t\t" ,end='\r')
			#time.sleep(0.5)
			try:
				response = requests.get(url + line,cookies=retrievedCookie,headers=headers)
				#print(line + "\t\t\t" + str(response.status_code))
				#time.sleep(0.5)
				if((response.status_code >= 100 and response.status_code <= 399) or response.status_code == 403):
					code = response.status_code
					itemType = "Directory"
					information = (line,code,itemType)
					if(response.content != errorPage): #If the request doesnt match the 404 page then continue 
						goodItems.append(information)
						directoriesFound.append(1)
						getServices(url+line,response,goodItems,cookies,serverInfo,servicesFound)
					else:
						print("404",end="\r")
						#input()
					#goodItems.append(information)
			except Exception as e:
				print(e)
				continue


		print("Scanning Directory Completed! ({} directories)\t\t\t\t\t\t".format(len(directoriesFound)))
		saveAndShowItems(url,goodItems,serverInfo,servicesFound,portsOpen,start)

		#End searching through common files
	else:
		print("Failed.: " + str(baseresponse.status_code))
		print("")
