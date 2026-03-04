# Beehavior-Inator 

Thie progject is a web-based honeypot built using the HoneyHTTPD framework. The Beehavior_inator honeypot simulates a web serice and recoreds HTTP requestes from users. Interactions with the sercive are recoreded and consistainly ansalyeted for potenintal attackers and normal traffic behavoir.  

HoneyHTTPD framwork servers are the core web sercer, while our implemetation extened it to run as a pubblilky accessible honeypot. 

## Live Deployment 

The honeypot is deployed at: 

https://www.sudo-cheese.org/

This server is hosted and maintain by the team. Traffic sent to these domain is handled by the Beehavior-Inator honeyport server and is logged for analysis. 

## Installation and Setup For Local Running

1. Clone or download this repo
2. Install dependencies: 
    * Python 2: `sudo pip install -r requirements.txt` 
    * Python 3: `sudo pip3 install -r requirements.txt` 
3. Activitate a vitual encironment via this command: 
    * `source .venv/bin/activate`
4. Run HoneyHTTPD with:
    * Python 2 `sudo python2 start.py --config config.json`
    * Python 3 `sudo python3 start.py --config config.json`

The server will start with the port, logging option, and serverhanlders defined in config.json. 

Caputured requries from running this server can be found in the logs/ directory. 

## Open Souce Software Used 

This project builds upon HoneyHTTPD, an open soucr python framework. Specically used for creating fack honeypots and websevers. 

This framwork provides: 
* HTTPS sever functionality 
* Modular server handlers 
* logging mechanisms 

HoneyHTTPD repository: 
https://github.com/bocajspear1/honeyhttpd

## Software Deveolped 

* Custom config.json: 
    - which ports the honeypots liston on 
    - which server modules are used 
    - log behavior  
    - HTTPS support 
* Custom Webpage: 
    - Desinged to appeare as a normal web sever, but allows us to capute requests from users, bots, attackers, and scanners. 
* Log Parsing 
    - Developed a scraced that helps process the honeypot logs before they are interprested by LLM. 
    - Inlcued soucre IP, timestamp, HTTP request method, request path 
    - Output stored as events.jsonl


## Sever and LLM Small explaination maybe 

## Technologies and Platformes Used 

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
