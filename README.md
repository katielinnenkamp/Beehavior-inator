# Beehavior-Inator


This project is a web-based honeypot built using the HoneyHTTPD framework. The Beehavior_inator honeypot simulates a web service and records HTTP requests from users. Interactions with the service are recorded and consistently analyzed for potential attackers and normal traffic behavior. 


HoneyHTTPD framework servers are the core web server, while our implementation extended it to run as a publicly accessible honeypot.


## Live Deployment


The honeypot is deployed at:


https://www.sudo-cheese.org/


This server is hosted and maintained by the team. Traffic sent to these domains is handled by the Beehavior-Inator honeyport server and is logged for analysis.


## Installation and Setup For Local Running


1. Clone or download this repo
2. Install dependencies:
   * Python 2: `sudo pip install -r requirements.txt`
   * Python 3: `sudo pip3 install -r requirements.txt`
3. Activate a virtual environment via this command:
   * `source .venv/bin/activate`
4. Run HoneyHTTPD with:
   * Python 2 `sudo python2 start.py --config config.json`
   * Python 3 `sudo python3 start.py --config config.json`


The server will start with the port, logging option, and server handlers defined in config.json.


Logs captured from running this server can be found in the logs/ directory locally or https://www.sudo-cheese.org/report.html


## Open Source Software Used


This project builds upon HoneyHTTPD, an open source python framework. Specifically used for creating fake honeypots and web servers.


This framework provides:
* HTTPS server functionality
* Modular server handlers
* logging mechanisms


HoneyHTTPD repository:
https://github.com/bocajspear1/honeyhttpd


## Software Developed


* Custom config.json:
   - which ports the honeypots liston on
   - which server modules are used
   - log behavior 
   - HTTPS support
* Custom Webpage:
   - Designed to appear as a normal web server, but allows us to capture requests from users, bots, attackers, and scanners.
* Log Parsing
   - Developed a scratch that helps process the honeypot logs before they are interpreted by LLM.
   - Include source IP, timestamp, HTTP request method, request path
   - Output stored as events.jsonl




## Sever and LLM Small explanation maybe


## Technologies and Platforms Used


* Python3
* HoneyHTTPD
* SEVER AND LLM THINGS HERE




## Generating SSL certificates


```
openssl req -new -x509 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
```


From [here](https://gist.github.com/dergachev/7028596).


## Contributing


Go at it! Open an issue, make a pull request, fork it, etc.


## License


This project is licensed under the Mozilla Public License, v2.0 (formerly GPL 3.0)



