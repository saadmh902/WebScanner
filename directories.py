import requests
import time
from datetime import date
import datetime
from urllib.parse import urlparse
import webbrowser
import os
from requests_html import HTMLSession
from bs4 import BeautifulSoup
import socket
import paramiko
import ftplib
from lxml.etree import ParserError
#####################################################################
#																	#
#	Written by Saad M 												#
#	Please excuse the messy code this is my first proper project	#
#						👉👈										#
#																	#
#####################################################################

# DISCLAIMER : Only use this tool for servers you have explicit permission to test on!
# I am not liable for any damage you cause!



def checkForFTP(url):#Check if FTP connections can be made
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

	loginIPs = [ip,"ftp."+ip,"files."+ip]
	for loginIP in loginIPs:
		for line in loginDictionary:
			try:
				session = ftplib.FTP(loginIP,line[0],line[1])
				print(session)
				print("FTP Access granted using user '" + line[0] + "' and pass '"+line[1]+"'")
			except socket.gaierror:
				print("Could not connect to FTP server")
			except ftplib.error_perm:
				print("FTP Auth Failed!")
			except TimeoutError:
				print("FTP Timeout!")
			except ConnectionRefusedError:
				print("FTP Connection Refused")
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
			print("Attempting to SSH with user: " + line[0] + " and pass: " + line[1])
			#username = "root"
			#password = "root"

			client = paramiko.client.SSHClient()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			client.connect(host, username=username, password=password)
			_stdin, _stdout,_stderr = client.exec_command("ls -l")
			print(stdout.read().decode())
			print("It looks like SSH access was made!")
			print("FTP Access granted using user '" + line[0] + "' and pass '"+line[1]+"'")
			#To do Add user and pass to report.html
			input()
			client.close()
		except socket.gaierror:
			print("SSH server not valid.")
			input()
			break
		except paramiko.ssh_exception.BadAuthenticationType:
			print("Connection to SSH made!\nCan't auth, requires ssh key.")
			input()
			break
		except paramiko.ssh_exception.NoValidConnectionsError:
			print("Could not make an SSH connection")
			break
			#input()
			#break



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
				

	

	#addService("Name To Be Displayed", [Dicitionary to be checked], array to check)
	addService("WordPress",["wp-admin","wp-content","wpo-plugins-tables-list","wordpress"],servicesFound)
	addService("cPanel",["cpanel"],servicesFound)
	addService("phpMyAdmin",["phpmyadmin"],servicesFound)


def getWebServerInfo(url,response,goodItems,cookies,serverInfo):#This is used on nginx/apache pages that divulge server information
	#print("Looking for server info...",end="\r")
	#r = requests.get(url)
	parser = BeautifulSoup(response.content, 'html.parser')#apache
	for line in parser.find_all("address"):
		print("[ALERT]: Retrieved Server Information: ("+line.decode_contents() + ") this information was found on "+url)
		information = (line.decode_contents(),"Server Info: ")
		serverInfo.append(information)
	for line in parser.find_all("center"):#nginx
		if "nginx" in line.decode_contents():
			information = (line.decode_contents(),"Server Info: ")
			serverInfo.append(information)	
			print("[ALERT]: Retrieved Server Information: ("+line.decode_contents() + ") this information was found on "+url)	

def scanRobots(url,goodItems,cookies):
	print("Scanning robots file for new items\t\t\t\t")
	blacklist = ["User-agent","Crawl-delay"]#Ignore populating from this list
	response = requests.get(url + "robots.txt",cookies)
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
			print(item + " found",end="\r")
			information = (item,"ROBOTS","OTHER")
			goodItems.append(information)
		except:continue

	print("Scanning robots completed!\t\t\t\t")

def saveAndShowItems(url,goodItems,serverInfo,servicesFound,portsOpen): #Show successful items and save data to report

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
		display_server_info = "<b>Server Information:</b><span>"+serverInfo[0][0]+"</span>"
	display_services = """
	<b>No Services were found</b>
	"""


	if(len(servicesFound) > 0): #Display services, wordpress cpanel roundcube etc
		display_services = "<table><tr><th>Services Found</th><th>-</th></tr>"
		for count,line in enumerate(servicesFound):
			display_services+= "<tr><td>" + line[0] +"</td><td>"+line[1] + "</td></tr>"
		display_services += "</table>"
			
	with open("exports/"+newFile, "w") as myfile:
		myfile.write('''
			<style>.orange { color:orange; } .green { color:green } .blue { color:blue } html { font-family:Arial; } </style>
			<h1>Scan Report: ''' +url + ' @ ' + newFileDate+'''</h1>
			'''+display_server_info+'''
			'''+display_services+'''
			<b>Total Items: '''+ str(len(goodItems))+'''</b>
			<table><tr><th>Item</th><th>Code</th><th>Type</th></tr><tr>''')

		for list in goodItems:#Iterate through good items, add them to report and display eeach item
			print(str(list[0]) + "\t<"+str(list[1])+">")
			href = url + str(list[0]) #Absolute path
			tdClass = ""
			if(list[1] == 200):
				tdClass = "green"
			elif(list[1] == 403):
				tdClass = "orange"
			elif(list[1] == "ROBOTS"):
				tdClass = "blue"
			if(list[2] == "HyperLink"):
				href = str(list[0]) #http://localhost/ instead of http://localhost/localhost/index.php
			myfile.write("<tr><td><a class='"+tdClass+"' href='"+href +"'> " + str(list[0]) + "</a></td><td>" + str(list[1]) + "</td><td>" + str(list[2]) + "</td></tr>")
		myfile.write("</table>")

		print("Services found:")#Iterate throguh servicesFound and display them
		for list in servicesFound:
			print(str(list[0]))
		

		#Ports

		checkForPorts(url,portsOpen)
		myfile.write("<h4>Ports Available:</h4>")
		for line in portsOpen:
			myfile.write("<p>Port: "+str(line)+"</p>")

		checkForSSH(url)
		checkForFTP(url)

		print("Data saved to exports/" + newFile)
		while(True):
			openReport = input("Open report? (Y/N): ")
			if(openReport.lower() == "y"):
				currentDir = os.path.abspath(os.getcwd())
				currentDir = currentDir.replace("\\","/")
				currentDir += "/exports/"
				openfile = 'file://'+currentDir+newFile
				#print(openfile)
				webbrowser.open(openfile, new=2)
				break
			elif(openReport.lower() == "n"):
				print("Skipped report.")
				break
			else:
				print("Please choose Y or N.")
	
def lookForLinks(url,cookie,goodItems): #This function opens successful files and looks for links
	print("Grabbing all links from: '"+url+"'\t\t\t\t", end="\r")
	sss = HTMLSession()
	k = sss.get(url)
	links = k.html.absolute_links #hrefs

	for line in links: #Fetches hrefs
		#print("Fetching hyperlinks from"+url,end="\r")
		#print("Checking if file '"+line+"' is good...\t\t\t\t\t\t",end="\r")
		my_hostname = urlparse(url)
		my_hostname ='{uri.netloc}'.format(uri=my_hostname)
		check_hostname = urlparse(line)
		check_hostname ='{uri.netloc}'.format(uri=check_hostname)
		if(my_hostname in check_hostname):#if line hosttname and URL hostname are same then append, e.g. http://localhost/index.php => http://localhost/post.php = Good http
			#print("'"+line+"' hyperlink found\t\t\t\t\t\t",end="\r")
			information = (line,"200","HyperLink")
			goodItems.append(information)

	r = requests.get(url)#Fetches actions
	parser = BeautifulSoup(r.content, 'html.parser')#Get form actions
	forms = [f.get('action') for f in parser.find_all('form')]
	for actionLine in forms:
		print("'"+actionLine+"' <form> action found\t\t\t\t\t\t",end="\r")
		information = (actionLine,"200","FORM ACTION")
		goodItems.append(information)


	

def scanDirectories(url,cookie):
	#start cookies
	if(cookie == "n"):
		cookies = {'': ''}
	else:
		cookies = {'PHPSESSID': 'uvv586vf9k499e0hasat211qio'}#Change to get from a cookiefile
	#end cookies
	goodItems = []
	serverInfo = []
	servicesFound = []
	portsOpen = []

	class commonFiles(): #Class for all files to search through

		# Each file will be checked against each extension
		# E.g. index => index.html index.php index.pl index.txt etc
		files = ["index","cgi"] #Typical index files
		files.extend([".htaccess",".htpasswd","robots"]) #Apache files
		files.extend(["404","405","503","504"]) #Error pages
		files.extend(["style","stylesheet","styles","css"]) #CSS 
		files.extend(["login","register","passwords","pass","passes","passwd","passwds","log-in","log","logs","signup","sign-up","logout","log-out"])#Auth files
		files.extend(["members","members_area","member","user","profile","users","members_list"]) #Profile files
		files.extend(["about","about_us","aboutus"]) #About us pages
		files.extend(["contactus","contact_us"]) #contact us pages
		files.extend(["gallery","photo","imag"]) #Gallerys
		files.extend(["js","java","javascript"])#JavaScript files/directories

		files.extend(["home","notice",]) #General files
		#files.extend(["oldindex","test","testadf","testasdf","testasf","t"]) #Files sometimes left behind devs
		#files.extend(["dev","development","testing"]) # more development files
		#files.extend(["wp-admin","phpmyadmin","cpanel"])
		extensions = [".html",".php",".htm",".shtml",".pl",".txt",".ico",".css",".js",""]
		deepExtensions = [".exe",".pdf",".png",".jpg",".jpeg",".zip",".rar",".asp",".aspx"]

		directories =  ["admin","admincp","cpanel","phpmyadmin","wp-admin","login","logout","settings","img","images","image","assets","register","dashboard","roundcube",":2096","downloads","download","dload","private","backup","backups","back-up"] #DIRECTORIES
		directories.extend(["tools"])
		wordpress = ["wp-content/uploads/wpo-plugins-tables-list.json"] #wordpress files


	print("Beginning scan of " + url)
	baseresponse = requests.get(url,cookies)
	if(baseresponse.status_code == 200 or baseresponse.status_code == 406 or baseresponse.status_code == 403):
		print("Success! Connected to "+ url)

		#Begin Scanning 
		#Scan common files

		timerDelay = 0.01
		commonFiles = commonFiles()
		for mainCount,line in enumerate(commonFiles.files):
			for count,extensions in enumerate(commonFiles.extensions):
				page = line + extensions
				print("Checking for file: '" + page + "' (" + str(mainCount) + "/" + str((len(commonFiles.files) * len(commonFiles.extensions))+ 1) +")\t\t\t\t\t\t" ,end='\r')
				time.sleep(timerDelay)
				try:
					response = requests.get(url + page,cookies)
					if((response.status_code >= 100 and response.status_code <= 399) or response.status_code == 403 or response.status_code == 406): ##If the file exists then save it
						code = response.status_code
						itemType = "File"
						information = (page,code,itemType)
						goodItems.append(information)
						getServices(page,response,goodItems,cookies,serverInfo,servicesFound)#Check if this page give service info e.g. phpmyadmin wordpress etc
						if(len(serverInfo) == 0):#If serverinfo wasnt already grabbed, collect info
							getWebServerInfo(url+page,response,goodItems,cookies,serverInfo)
						if(code == 200):#The page is good, now check it for any other links
							lookForLinks(url + page,cookie,goodItems)
						if(page == "robots.txt"): ##If robots.txt is good then scan the robots doc
							scanRobots(url,goodItems,cookies)
				except ParserError:
					print("Request was empty ignoring...\t\t\t\t\t\t\t")
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

		print("Scanning Files Completed!\t\t\t\t\t\t")

		#Scan common directories
		for count,line in enumerate(commonFiles.directories):
			print("Checking for directory: '" + line + "' (" + str(count) + "/" + str(len(commonFiles.directories) + 1) +")\t\t\t\t\t" ,end='\r')
			#time.sleep(0.5)
			try:
				response = requests.get(url + line,cookies)
				#print(line + "\t\t\t" + str(response.status_code))
				#time.sleep(0.5)
				if((response.status_code >= 100 and response.status_code <= 399) or response.status_code == 403):
					code = response.status_code
					itemType = "Directory"
					information = (line,code,itemType)
					goodItems.append(information)
					getServices(url+line,response,goodItems,cookies,serverInfo,servicesFound)
			except Exception as e:
				print(e)
				continue


		print("Scanning Directories Completed!\t\t\t\t")
		saveAndShowItems(url,goodItems,serverInfo,servicesFound,portsOpen)

		#End searching through common files
	else:
		print("Failed.: " + str(baseresponse.status_code))
		print("")