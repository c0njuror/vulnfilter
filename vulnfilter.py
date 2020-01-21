
"""
Vulnfilter.py - by Kenny Jansson, 2019

The script includes examples of how to simulate web vulnerabilities on a web site, and use this as part of a Capture The Flag event (CTF).

mitmproxy allows you to modify HTTP content, and when you have full access to alter the response in any way you like, you can also introduce any vulnerabilities you like as a PoC/CTF challenge.
For advanced backend vulnerabilities such as XXE, Command Injection, SQL injection etc. that requires a more dynamic response you can modify the response to point the browser to your vulnerable backend server.

Howto connect:
 - import /.mitmproxy/mitmproxy-ca.pem into the browser and proxy tool.
 - Create a new profile or go to History in your browser and press forget URL on any URL that you want to run through this filter.
 - Point your proxy tool such as Burp Suite proxy to upstream to the IP of mitmproxy and port 8080. Point your browser to your proxy tool.

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

def response(flow: http.HTTPFlow) -> None:

### RE-ROUTING EXAMPLES ####

   # match and replace if url ends with script.js (this will have the effect of changing example.org in that particular script to 192.168.1.1:8070)
#    if flow.request.pretty_url.endswith("/util/login.aspx"):
#        tag_pattern = b'example.org'
#        flow.response.content = re.sub(tag_pattern, b'192.168.1.1:8070', flow.response.content, flags=re.IGNORECASE)

   # match and replace and use jquery to overwrite the form (this could be used to reroute form posts to another server that runs a vulnerable SQLserver etc.)
#    if flow.request.pretty_url.endswith("login.html"):
#        tag_pattern = b'<BODY>'
#        flow.response.content = re.sub(tag_pattern, b'<BODY><SCRIPT>$("form").attr("action", "http://192.168.1.1:8070/NEWaction.php");</SCRIPT>', flow.response.content, flags=re.IGNORECASE)

   # If action.php, change the host header to point to another server (this could be used to reroute form posts to another server that runs a vulnerable SQLserver, Cmdinjection etc.)
#    if "example.org/action.php" in flow.request.pretty_url:
#        url = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
#        last = url.split('action.php')[1] #Get whats after action.php so that the parameters are included. 
#        flow.response = http.HTTPResponse.make(
#            302,  # (optional) status code
#            b"",  # (optional) content
#            {"Location": 'http://192.168.0.1/action.php' + last}  # (optional) headers
#        )

    # Forward the value of the sql parameter to a server on port 800, or any website that has a sql injection and send the response back (could be used to demonstrate SQL injection or any parameter injection)
#    if "?sql=" in flow.request.pretty_url:
#        url = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
#        last = url.split('sql=')[1] #Get whats after sql=
#        f=urlopen('http://127.0.0.1:80/index.php?query=%s' % last)
#        remoteValue=f.read()
#       custom_response=http.HTTPResponse.make(200,remoteValue,{},)
#        flow.response.content=custom_response.content

    # Forward the value of the sql parameter to a server on port 800 and send the response back where the text 'result.' occurs (could be used to simulate SQL injection in a search query)
    # For this example to work you need to have an sql injection in the sql parameter on b.php running on 172.31.41.250:90. This can be setup easy with a PHP/MSSQL docker instance such as mssql-php-msphpsql
    if "?q=" in flow.request.pretty_url:
        url = flow.request.path
        last = url.split('q=')[1] #Get whats after query=
        f=urlopen('http://172.31.41.250:90/b.php?sql=%s' % last)
        remoteValue=f.read()
        flow.response.content = re.sub(b'result.',b'result.' + remoteValue, flow.response.content, flags=re.IGNORECASE)


### MISC EXAMPLES ####

   # CORS - Allow any origin (you could modify any response headers this way).
#    flow.response.headers['Access-Control-Allow-Origin'] = "*"

   # strip text in response body (in case you would like to replace some text in the response)
#    flow.response.content = flow.response.content.replace(b'that code is invalid', b'the code')

    # match and replace pattern in response body (could be used to demonstrate comments that contains too much information)
#    if flow.request.pretty_url.endswith("/script.js"):
#        tag_pattern = b'<script>'
#        flow.response.content = re.sub(tag_pattern, b'<script>//flag:8F4B96646F01AB7AA64A1814ECCB232B' + flow.request.pretty_url, flow.response.content, flags=re.IGNORECASE)

  # modify reponse if full url matches (could be used to demonstrate command injection - static response)
#    if flow.request.pretty_url == "https://www.example.org/?cmd=whoami":
#        flow.response = http.HTTPResponse.make(
#            200,  # (optional) status code
#            b'Flag: 8F4B96646F01AB7AA64A1814ECCB232B \n root',  # (optional) content
#            {"Content-Type": "text/plain"}  # (optional) headers
#        )

### DIRECTORY/FILE BRUTEFORCE EXAMPLES ####

   # add header if url ends with /api (could be used to demonstrate directory brute force on ANY domain)
#    if flow.request.pretty_url.endswith("/api"):
#        flow.response.headers["flag"] = "8F4B96646F01AB7AA64A1814ECCB232B"

    # modify reponse if full url matches (could be used to demonstrate directory brute force of a specific domain, in this case robots.txt)
    if flow.request.pretty_url == "https://www.ExampleCompany.se/robots.txt":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"User-agent: *\n"+  # (optional) content
            b"Disallow: /backup/\n"+  # (optional) content
#            b"Disallow: /admin/\n"+
            b"Flag: 70fb04ad7ce7bad7a9f78e46ef139627",  # (optional) content
            {"Content-Type": "text/plain"}  # (optional) headers
        )

    # modify reponse if full url matches (could be used to demonstrate directory brute force of a specific domain, in this case an old version of a php webpage that is hinted to in robots.txt above)
    if flow.request.pretty_url == "https://www.ExampleCompany.se/backup/index.old":
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"<% response.write(1); \n //Response is 1 when this site is alive. Password for www account is www. \n%>  \n\n 6b59011094839630e6b6e04a970a1a22",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )

    # modify reponse if url ends with (could be used to demonstrate directory brute force on ANY domain)
#    if flow.request.pretty_url.endswith("/end"):
#        flow.response = http.HTTPResponse.make(
#            200,  # (optional) status code
#            b"Flag: 8F4B96646F01AB7AA64A1814ECCB230B",  # (optional) content
#            {"Content-Type": "text/html"}  # (optional) headers
#        )

### XSS EXAMPLES ####

   # match pattern and add Script Alert in response body (could be used to simply test whether the mitmproxy setup works as intended)
    if flow.request.pretty_url.endswith("/alertbox"):
        tag_pattern = b'<script>'
        flow.response.content = re.sub(tag_pattern, b'<script>alert("942dd86b25a2cd8e488742bf20dcbc28")</script><script>', flow.response.content, flags=re.IGNORECASE)

   # If URL ends with %00, match replace with the current URL and decode to UTF (could be used to demonstrate XSS in a reflected URL when matching a specific ending)
#    if flow.request.pretty_url.endswith("%00"):
#        tag_pattern = b'<script>'
#        tag_replace = urllib.parse.unquote(flow.request.pretty_url) #Decodes URL to UTF
#        flow.response.content = re.sub(tag_pattern, str.encode(tag_replace)+b'<script>', flow.response.content, flags=re.IGNORECASE)

   # If URL is https://www.example.org/?s= then add whatever is behind this parameter and display it on the web page in UTF (Used to demonstrate reflected XSS in a specific parameter).
#    if "https://www.example.org/?s=" in flow.request.pretty_url:
#        tag_pattern = b'search terms'
#        tag_replace = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
#        tag_replace = tag_replace.split('=')[1] #Only show whats after the first equal sign..
#        flow.response.content = re.sub(tag_pattern, b'search term '+str.encode(tag_replace), flow.response.content, flags=re.IGNORECASE)

   # If URL is https://www.example.org/?s=<script> then alert a response (could be used to help on the way to finding an XSS (when one inject <script> into the s parameter they get an alert box)
#    if "https://www.example.org/?s=%3Cscript%3E" in flow.request.pretty_url:
#        tag_pattern = b'<head>'
#        flow.response.content = re.sub(tag_pattern, b'<script>alert("Congratulations! Your first flag is: 8F4B96646F01AB7AA64A1814ECCB230B")</script><head>',flow.response.content, flags=re.IGNORECASE)

   # If URL is https://www.bsideslv.org/donors/?eventID= then alert whatever is behind the eventID parameter (simulates an eventID parameter on bsideslv.org and reflects the value in response body)
#    if "https://www.bsideslv.org/donors/?eventID=" in flow.request.pretty_url:
#        tag_pattern = b'This page last updated'
#        tag_replace = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
#        tag_replace = tag_replace.split('eventID=')[1] #Only show whats after eventID=..
#        flow.response.content = re.sub(tag_pattern, b'Event ID: '+str.encode(tag_replace)+b'<br><br>This page last updated', flow.response.content, flags=re.IGNORECASE)

   # Reflect content of q parameter in decoded format on bing (simulates an XSS in the search query on bing)
#    if "https://www.bing.com/search?q=" in flow.request.pretty_url:
#        tag_pattern = b'page.serp%26bq%3d'
#        tag_replace = urllib.parse.unquote(flow.request.path) #Decodes URL to UTF
#        flow.response.content = re.sub(tag_pattern, b'page.serp%26bq%3d '+str.encode(tag_replace), flow.response.content, flags=re.IGNORECASE)

### PATH TRAVERSAL EXAMPLES ####

    # On some other machine, setup an nginx with: run sudo docker pull nginx && sudo docker run --name nginxPT -p 81:80 -d nginx && sudo docker exec nginxPT / /usr/share/nginx/html/root
    # The /etc/hosts file will now reflect when browsing to www.example.com/globalassets/..%2f..%2f..%2f..%2fetc/hosts
    # You can add or modify any file you want in the docker image, which will ofcoure reflect when using the path traversal.
    if "globalassets/..%2f..%2f..%2f..%2f" in flow.request.pretty_url:
        last = flow.request.path.split('..%2f..%2f..%2f..%2f')[1] #Get whats after 4 ..%2f
        f=urlopen("http://172.31.34.148:81/root/%s" % last)
        remoteFile=f.read()
        custom_response=http.HTTPResponse.make(
            200,
            remoteFile,
                {},
        )
        flow.response.content=custom_response.content


   # modify reponse if full url matches (could be used to demonstrate path traversal - you can make multiple of these with other files if you dont wanna setup a server for this purpose)
#    if flow.request.pretty_url == "https://www.example.org/../../../etc/passwd":
#        flow.response = http.HTTPResponse.make(
#            200,  # (optional) status code
#            b"Flag: 8F4B96646F01AB7AA64A1814ECCB230B\n"+
#            b"root:password",  # (optional) content
#            {"Content-Type": "text/html"}  # (optional) headers
#        )

    # modify reponse if url matches ?file=../../../etc/passwd and include a local file (could be used to demonstrate path traversal - you can  make multiple of these with other files if you dont wanna setup a server for this purpose)
#    if "?file=../../../etc/passwd" in flow.request.pretty_url:
#        f=open("/root/test/mitm/files/passwd.txt","rb")
#        localFile=f.read()
#        custom_response=http.HTTPResponse.make(
#            200,
#           localFile,
#                {},
#        )
#        flow.response.content=custom_response.content


    # modify reponse if url matches ?file=iso_8859-1.txt and include a remote file 
#    if "?file=../../../iso_8859-1.txt" in flow.request.pretty_url:
#        f=urlopen("http://www.w3.org/TR/PNG/iso_8859-1.txt")
#        remoteFile=f.read()
#        custom_response=http.HTTPResponse.make(
#            200,
#            remoteFile,
#                {},
#        )
#        flow.response.content=custom_response.content



### AUTHENTICATION EXAMPLES ###

    # simulate authentication (could be used to demonstrate brute force)
    if "/admin/login.php?username=" in flow.request.pretty_url:
        if "/admin/login.php?username=admin&password=ExampleCompany_ADMIN_2012" in flow.request.pretty_url:
            flow.response = http.HTTPResponse.make(
                200,  # (optional) status code
                b"Flag: 8F4B96646F01AB7AA64A1814ECCB232B <br>"+
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




def request(flow):
     
    # Respond with "out of scope" if going out of scope. 
    list = ["ExampleCompany.se","anotherexample.no","http://172.31.32.75:8080","amazonaws.com","example2.org"]
    inurl="false"
    for item in list:
        if item in flow.request.pretty_url:
            inurl="true"
            break
    if "true" not in inurl:
        flow.response = http.HTTPResponse.make(
            401,
            b'Out of Scope!\n'

        )

    #Log all requests
    if "www.ExampleCompany.se" in flow.request.pretty_url:
        cli_ip = flow.client_conn.address.host
        f = open('/tmp/mitmhttplogs.txt', 'a+')
        f.write(cli_ip + " -> " + flow.request.url + '\n')
        f.close()

    #If going to /server, respond with a basic authentication prompt, respond with flag value as well as set a cookie with the flag value, then return to main site - can be used to for brute force (located here because its part of def request). 
    server = 'https://www.ExampleCompany.se/server'
    lowerurl = flow.request.pretty_url.lower()
    if server in lowerurl:
        creds = flow.request.headers.get('authorization','null')
        if "d3d3Ond3dw==" in creds: #Creds www:www
            flow.response = http.HTTPResponse.make(
                302,
                b'Authenticated\n'+
                b'Flag: 39181719efff00b70793a11dc1dcc001',
                {"Set-Cookie": 'Flag=39181719efff00b70793a11dc1dcc021',"Location": 'https://www.ExampleCompany.se'}  # (optional) headers

            )
        else:
            flow.response = http.HTTPResponse.make(
                401,  # (optional) status code
                b'Unauthenticated',  # (optional) content
                {"WWW-Authenticate": "Basic realm=\"ExampleCompany WWW Admin\""}  # (optional) headers
            )


