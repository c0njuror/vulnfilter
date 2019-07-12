# vulnfilter
Vulnerable filter framework for web applications

# Usage
mitmproxy -s vulnfilter.py

# Description

The script includes examples of how to introduce "fake" web vulnerabilities into a web site, and use this as part of a Capture The Flag event (CTF). 

mitmproxy allows you to modify HTTP content, and when you have full access to alter the response in any way you like, you can also introduce any vulnerabilities you like as a PoC/CTF challenge.
For advanced backend vulnerabilities such as XXE, Command Injection, SQL injection etc. that requires a more dynamic response you can modify the response to point the browser to your vulnerable backend server. 

The first part of the script is based on the SSLstrip-script that comes with mitmproxy.



# Two ways to connect: 

Way 1: As a normal proxy
 - import /.mitmproxy/mitmproxy-ca.pem into the browser and proxy tool.
 - Go to History in your browser and press forget URL on any URL that you want to run through this filter.
 - Point your proxy tool such as Burp Suite proxy to upstream to the IP of mitmproxy and port 8080. Point your browser to your proxy tool. 

Way 2: As a reverse proxy
 - If your website has a wildcard certificate you can create a subdomain on your website (e.g. hack.example.org) and use nginx on the subdomain and point it to your mitmproxy (proxy_pass http://127.0.0.1:8080)
 - NB: you would have to use a rewrite rule and rewrite allt links to example.org to hack.example.org (flow.response.content = flow.response.content.replace(b'example.org', b'hack.example.org')

