import requests
import time
import sys
from directories import scanDirectories


#####################################################################
#																	#
#	Written by Saad M 												#
#	Please excuse the messy code this is my first proper project	#
#						👉👈										#
#																	#
#####################################################################

# DISCLAIMER : Only use this tool for servers you have explicit permission to test on!
# I am not liable for any damage you cause!


print("Choose one of the following options")
print("-------------------------------------")
print("1:\tScan for directories")
print("2:\tScan for XSS")
print("3:\tScan for insecure GET paramaters")
print("-------------------------------------")
print("\n")



#scanDirectories("http://localhost/","y")


while(True):
	chooseOption = input("Choose option:")
	if(chooseOption == "1"):
		url = input("Enter base website url ('E.g. http://google.com/': ")
		scanDirectories(url,"n")
	else:
		print("Invalid option. try again!")