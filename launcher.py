import requests
import time
import sys
from directories import scanDirectories,checkForFTP,checkForSSH
from xss import scanXSS


#####################################################################
#																	#
#	Written by Saad M 												#
#	Please excuse the messy code this is my first proper project	#
#						👉👈										#
#																	#
#####################################################################

# DISCLAIMER : Only use this tool for servers you have explicit permission to test on!
# I am not liable for any damage you cause!


#scanDirectories("http://localhost/","y")


while(True):
	print("Choose one of the following options\t")
	print("-------------------------------------")
	print("1:\tScan for directories")
	print("2:\tScan for directories with DirBuster list (Long)")
	print("3:\tScan for XSS")
	print("4:\tScan for insecure GET parameters")
	print("5:\tBrute force SSH")
	print("6:\tBrute force FTP")
	print("q:\tExit")
	print("-------------------------------------")
	print("\n")
	chooseOption = input("Choose option:")
	if(chooseOption == "1"):
		url = input("Enter base website url ('E.g. http://google.com/'): ")
		#url="http://localhost/minecraftlookup/"
		scanDirectories(url,"n",0)
	elif(chooseOption == "2"):
		url = input("Enter base website url ('E.g. http://google.com/'): ")
		scanDirectories(url,"n",1)
	elif(chooseOption == "5"):
		url = input("URL: ")
		checkForSSH(url)
	elif(chooseOption == "6"):
		url = input("URL: ")
		print("0:\tCheck against simple credential list (Quick)")
		print("1:\tCheck against large credential list (Long)")
		search_level = int(input("Choose Selection:"))
		checkForFTP(url,search_level)
	elif(chooseOption == "q"):
		exit()
	else:
		print("Invalid option. try again!")
