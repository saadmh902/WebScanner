# WebScanner
Scan a target URL for common links, open ports, services and vulnerabilities. Used for simple info gathering
<h1>Web Scanner</h1>
<img src="https://i.imgur.com/ClAJrqS.gif" width="1000" />
<img src="https://i.imgur.com/rTxWOuC.png" width="650" />
<h3>What is it used for?</h3>
<p>This scans a website for common files that might be left behind by the developer</p>

<h3>How does it work?</h3>
<pre>This looks for OS and version information for software such as apache/nginx
Then it crawls on each page for all links including &lt;form&gt; actions and &lt;a&gt; hrefs
Next it looks for common directories such as /phpmyadmin /cpanel /wp-admin etc
After this it sees what ports are open and tests if FTP and SSH connections are able to be made
WHOIS Lookup and reverse domain name lookup is performed 
All pages with GET paramaters are tested for simple SQL injection errors
Finally it writes everything to a report.html page so the user has a good idea of how the site is layed out.</pre>
