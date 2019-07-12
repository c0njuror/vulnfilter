"""
Vulnfilter.py - by Kenny Jansson, 2019

The script includes examples of how to introduce "fake" web vulnerabilities into a web site, and use this as part of a Capture The Flag event (CTF). 

mitmproxy allows you to modify HTTP content, and when you have full access to alter the response in any way you like, you can also introduce any vulnerabilities you like as a PoC/CTF challenge.
For advanced backend vulnerabilities such as XXE, Command Injection, SQL injection etc. that requires a more dynamic response you can modify the response to point the browser to your vulnerable backend server. 

The first part of the script is based on the SSLstrip-script that comes with mitmproxy.

Two ways to connect: 

Way 1: As a normal proxy
 - import /.mitmproxy/mitmproxy-ca.pem into the browser and proxy tool.
 - Go to History in your browser and press forget URL on any URL that you want to run through this filter.
 - Point your proxy tool such as Burp Suite proxy to upstream to the IP of mitmproxy and port 8080. Point your browser to your proxy tool. 

Way 2: As a reverse proxy
 - If your website has a wildcard certificate you can create a subdomain on your website (e.g. hack.example.org) and use nginx on the subdomain and point it to your mitmproxy (proxy_pass http://127.0.0.1:8080)
 - NB: you would have to use a rewrite rule and rewrite all links to example.org to hack.example.org (flow.response.content = flow.response.content.replace(b'example.org', b'hack.example.org')


"""

import re
import urllib.parse
import typing  # noqa
from mitmproxy import http
from mitmproxy import ctx
import urllib
from urllib.request import urlopen

# set of SSL/TLS capable hosts
secure_hosts: typing.Set[str] = set()


### SSL STRIP ####

def request(flow: http.HTTPFlow) -> None:
    flow.request.headers.pop('If-Modified-Since', None)
    flow.request.headers.pop('Cache-Control', None)

    # do not force https redirection
    flow.request.headers.pop('Upgrade-Insecure-Requests', None)

    # proxy connections to SSL-enabled hosts
    if flow.request.pretty_host in secure_hosts:
        flow.request.scheme = 'https'
        flow.request.port = 443

        # We need to update the request destination to whatever is specified in the host header:
        # Having no TLS Server Name Indication from the client and just an IP address as request.host
        # in transparent mode, TLS server name certificate validation would fail.
        flow.request.host = flow.request.pretty_host


def response(flow: http.HTTPFlow) -> None:
    flow.response.headers.pop('Strict-Transport-Security', None)
    flow.response.headers.pop('Public-Key-Pins', None)

    # strip links in response body
#    flow.response.content = flow.response.content.replace(b'https://', b'http://')

    # strip meta tag upgrade-insecure-requests in response body
    csp_meta_tag_pattern = b'<meta.*http-equiv=["\']Content-Security-Policy[\'"].*upgrade-insecure-requests.*?>'
    flow.response.content = re.sub(csp_meta_tag_pattern, b'', flow.response.content, flags=re.IGNORECASE)

    # strip links in 'Location' header
#    if flow.response.headers.get('Location', '').startswith('https://'):
#        location = flow.response.headers['Location']
#        hostname = urllib.parse.urlparse(location).hostname
#        if hostname:
#            secure_hosts.add(hostname)
#        flow.response.headers['Location'] = location.replace('https://', 'http://', 1)

    # strip upgrade-insecure-requests in Content-Security-Policy header
    if re.search('upgrade-insecure-requests', flow.response.headers.get('Content-Security-Policy', ''), flags=re.IGNORECASE):
        csp = flow.response.headers['Content-Security-Policy']
        flow.response.headers['Content-Security-Policy'] = re.sub('upgrade-insecure-requests[;\s]*', '', csp, flags=re.IGNORECASE)

    # strip secure flag from 'Set-Cookie' headers in responses (used to demonstrate difference in behavior when the secure flag is not set)
    cookies = flow.response.headers.get_all('Set-Cookie')
    cookies = [re.sub(r';\s*secure\s*', '', s) for s in cookies]
    flow.response.headers.set_all('Set-Cookie', cookies)

# SSL STRIP END #

### RE-ROUTING EXAMPLES ####

   # match and replace if url ends with script.js (this will have the effect of changing example.org in that particular script to 192.168.1.1:8070)
    if flow.request.pretty_url.endswith("script.js"): 
        tag_pattern = b'example.org'
        flow.response.content = re.sub(tag_pattern, b'192.168.1.1:8070', flow.response.content, flags=re.IGNORECASE)

   # match and replace and use jquery to overwrite the form (this could be used to reroute form posts to another server that runs a vulnerable SQLserver etc.) 
    if flow.request.pretty_url.endswith("login.html"): 
        tag_pattern = b'<BODY>'
        flow.response.content = re.sub(tag_pattern, b'<BODY><SCRIPT>$("form").attr("action", "http://192.168.1.1:8070/NEWaction.php");</SCRIPT>', flow.response.content, flags=re.IGNORECASE)


   # If action.php, change the host header to point to another server (this could be used to reroute form posts to another server that runs a vulnerable SQLserver, Cmdinjection etc.) 
    if "example.org/action.php" in flow.request.pretty_url:   
        url = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
        last = url.split('action.php')[1] #Get whats after action.php so that the parameters are included.   
        flow.response = http.HTTPResponse.make(
            302,  # (optional) status code
            b"",  # (optional) content
            {"Location": 'http://192.168.0.1/action.php' + last}  # (optional) headers    
        )

    # forward the value of the sql parameter to an internal server on port 800, or any website that has a sql injection and send the response back (could be used to demonstrate SQL injection or any parameter injection)
    if "?sql=" in flow.request.pretty_url:
        url = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
        last = url.split('sql=')[1] #Get whats after sql=
        f=urlopen('http://127.0.0.1:800/index.php?SQLparam=%s' % last)
        remoteValue=f.read()
        custom_response=http.HTTPResponse.make(200,remoteValue,{},)
        flow.response.content=custom_response.content


### MISC EXAMPLES ####

   # CORS - Allow any origin (you could modify any response headers this way).
#    flow.response.headers['Access-Control-Allow-Origin'] = "*"

   # strip text in response body (in case you would like to replace some text in the response)
    flow.response.content = flow.response.content.replace(b'that code is invalid', b'the code')

    # match and replace pattern in response body (could be used to demonstrate comments that contains too much information)
    if flow.request.pretty_url.endswith("/script.js"): 
        tag_pattern = b'<script>'
        flow.response.content = re.sub(tag_pattern, b'<script>//flag:8F4B96646F01AB7AA64A1814ECCB230B' + flow.request.pretty_url, flow.response.content, flags=re.IGNORECASE)

  # modify reponse if full url matches (could be used to demonstrate command injection - static response)
    if flow.request.pretty_url == "https://www.example.org/?cmd=whoami":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b'Flag: 8F4B96646F01AB7AA64A1814ECCB230B \n root',  # (optional) content
            {"Content-Type": "text/plain"}  # (optional) headers
        )

### DIRECTORY/FILE BRUTEFORCE EXAMPLES ####

   # add header if url ends with /api (could be used to demonstrate directory brute force on ANY domain)
    if flow.request.pretty_url.endswith("/api"): 
        flow.response.headers["flag"] = "8F4B96646F01AB7AA64A1814ECCB230B"

    # modify reponse if full url matches (could be used to demonstrate directory brute force of a specific domain, in this case robots.txt)
    if flow.request.pretty_url == "https://www.example.org/robots.txt":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"User-agent: *\n"+  # (optional) content
            b"Disallow: /backup/\n"+  # (optional) content
            b"Flag: 8F4B96646F01AB7AA64A1814ECCB230B",  # (optional) content
            {"Content-Type": "text/plain"}  # (optional) headers
        )

    # modify reponse if full url matches (could be used to demonstrate directory brute force of a specific domain, in this case an old version of a php webpage that is hinted to in robots.txt above)
    if flow.request.pretty_url == "https://www.example.org/backup/index.old":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"<?php flag=8F4B96646F01AB7AA64A1814ECCB230B ?>",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )

    # modify reponse if url ends with (could be used to demonstrate directory brute force on ANY domain)
    if flow.request.pretty_url.endswith("/end"): 
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"Flag: 8F4B96646F01AB7AA64A1814ECCB230B",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers    
        )
 
### XSS EXAMPLES ####

   # match pattern and add Script Alert in response body (could be used to simply test whether the mitmproxy setup works as intended)
    if flow.request.pretty_url.endswith("/xsstest"): 
        tag_pattern = b'<script>'
        flow.response.content = re.sub(tag_pattern, b'<script>alert(1)</script><script>', flow.response.content, flags=re.IGNORECASE)

   # If URL ends with %00, match replace with the current URL and decode to UTF (could be used to demonstrate XSS in a reflected URL when matching a specific ending)
    if flow.request.pretty_url.endswith("%00"): 
        tag_pattern = b'<script>'
        tag_replace = urllib.parse.unquote(flow.request.pretty_url) #Decodes URL to UTF
        flow.response.content = re.sub(tag_pattern, str.encode(tag_replace)+b'<script>', flow.response.content, flags=re.IGNORECASE)

   # If URL is https://www.example.org/?s= then add whatever is behind this parameter and display it on the web page in UTF (Used to demonstrate reflected XSS in a specific parameter). 
    if "https://www.example.org/?s=" in flow.request.pretty_url: 
        tag_pattern = b'search terms'
        tag_replace = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
        tag_replace = tag_replace.split('=')[1] #Only show whats after the first equal sign..
        flow.response.content = re.sub(tag_pattern, b'search term '+str.encode(tag_replace), flow.response.content, flags=re.IGNORECASE)

   # If URL is https://www.example.org/?s=<script> then alert a response (could be used to help on the way to finding an XSS (this when one inject <script> into the s parameter they get an alert box)
    if "https://www.example.org/?s=%3Cscript%3E" in flow.request.pretty_url: 
        tag_pattern = b'<head>'
        flow.response.content = re.sub(tag_pattern, b'<script>alert("Congratulations! Your first flag is: 8F4B96646F01AB7AA64A1814ECCB230B")</script><head>',flow.response.content, flags=re.IGNORECASE)
 
   # If URL is https://www.bsideslv.org/donors/?eventID= then alert whatever is behind the eventID parameter (simulates an eventID parameter on bsideslv.org and reflects the value in response body)
    if "https://www.bsideslv.org/donors/?eventID=" in flow.request.pretty_url: 
        tag_pattern = b'This page last updated'
        tag_replace = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
        tag_replace = tag_replace.split('eventID=')[1] #Only show whats after eventID=..
        flow.response.content = re.sub(tag_pattern, b'Event ID: '+str.encode(tag_replace)+b'<br><br>This page last updated', flow.response.content, flags=re.IGNORECASE)

   # Reflect content of q parameter in decoded format on bing (simulates an XSS in the search query on bing)
    if "https://www.bing.com/search?q=" in flow.request.pretty_url: 
        tag_pattern = b'page.serp%26bq%3d'
        tag_replace = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
        #tag_replace = tag_replace.split('=')[1] #Only keep whats after the first = sign..
        #tag_replace = tag_replace.split('&')[0] #Only keep whats before the first & sign..
        flow.response.content = re.sub(tag_pattern, b'page.serp%26bq%3d '+str.encode(tag_replace), flow.response.content, flags=re.IGNORECASE)

### PATH TRAVERSAL EXAMPLES ####

   # modify reponse if full url matches (could be used to demonstrate path traversal - you can ofcourse make multiple of these with other files)
    if flow.request.pretty_url == "https://www.example.org/../../../etc/passwd":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"Flag: 8F4B96646F01AB7AA64A1814ECCB230B\n"+
            b"root:password",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )

    # modify reponse if url matches ?file=../../../etc/passwd and include a local file (could be used to demonstrate path traversal - you can ofcourse make multiple of these with other files)
    if "?file=../../../etc/passwd" in flow.request.pretty_url:
        f=open("/root/test/mitm/files/passwd.txt","rb")
        localFile=f.read()
        custom_response=http.HTTPResponse.make(
            200,
            localFile,
                {},
        )
        flow.response.content=custom_response.content
        
    # modify reponse if url matches ?file=../../../etc/passwd and include a local file (could be used to demonstrate path traversal - you can ofcourse make multiple of these with other files)
    if "?file=../../../etc/passwd" in flow.request.pretty_url:
        f=open("/root/test/mitm/files/passwd.txt","rb")
        localFile=f.read()
        custom_response=http.HTTPResponse.make(
            200,
            localFile,
                {},
        )
        flow.response.content=custom_response.content

    # modify reponse if url matches ?file=../../../iso_8859-1.txt and include a remote file (could be used to demonstrate path traversal - you can ofcourse make multiple of these with other files)
    # you could also make this an arbitrary file read (look at next example for inspiration).
    if "?file=../../../iso_8859-1.txt" in flow.request.pretty_url:
        f=urlopen("http://www.w3.org/TR/PNG/iso_8859-1.txt")
        remoteFile=f.read()
        custom_response=http.HTTPResponse.make(
            200,
            remoteFile,
                {},
        )
        flow.response.content=custom_response.content

    # modify reponse if url matches ?file=../../../etc/passwd and include an arbitrary local file (could be used to demonstrate path traversal - you can ofcourse make multiple of these with other files)
    # if you create the file /root/test/mitm/files/etc/passwd on the server, then by requesting ?file=../../../../etc/passwd in the browser you would get this file. Use with caution. 
    if "?file=../../../../" in flow.request.pretty_url:
        url = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
        last = url.split('../../../../')[1] #Get whats after ../../../ 
        f=open('/root/test/mitm/files/%s' % last,"rb")
        localFile=f.read()
        custom_response=http.HTTPResponse.make(200,localFile,{},)
        flow.response.content=custom_response.content

### AUTHENTICATION EXAMPLES ###

    # simulate authentication (could be used to demonstrate brute force)
    if "login.php?username=" in flow.request.pretty_url:
        if "login.php?username=admin&password=123456" in flow.request.pretty_url:
            flow.response = http.HTTPResponse.make(
                200,  # (optional) status code
                b"Flag: 8F4B96646F01AB7AA64A1814ECCB230B <br>"+
                b"You have successfully authenticated!",  # (optional) content
                {"Content-Type": "text/html"}  # (optional) headers
            )
            flow.response.content=custom_response.content
        else:
            flow.response = http.HTTPResponse.make(
            403,  # (optional) status code
            b"Wrong username or password!",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
            )
            flow.response.content=custom_response.content
        

