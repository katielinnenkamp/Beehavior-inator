# Beehavior-Inator


This project is a web-based honeypot built using the HoneyHTTPD framework. The Beehavior_inator honeypot simulates a web service and records HTTP requests from users. Interactions with the service are recorded and consistently analyzed for potential attackers and normal traffic behavior. 


HoneyHTTPD framework servers are the core web server, while our implementation extended it to run as a publicly accessible honeypot.


## Live Deployment


The honeypot is deployed at:


https://www.sudo-cheese.org/

The honeypot reports can be found at:


https://www.sudo-cheese.org/report.html


The website pages are:
- archive.html
- createacc.html
- report.html
- standin.html
- 90.html
- pages/*
- archive/*


This server is hosted and maintained by the team. Traffic sent to these domains is handled by the Beehavior-Inator honeyport server and is logged for analysis.

## System Requirements


To run the current project exactly, the general recommendations is having an server with the following:
   * 16 GB RAM
   * Intel(R) Core(TM) i5-9500 CPU @ 3.00GHz
   * Integrated Intel® HD Graphics 610/630

If you have batter specs, you can change out the LLM model for one with more computing power. This is what's hosting the current project and thus our bare minimum.

## Ubuntu Server Setup

1. Install Ubuntu and setup SSH (follow along to the ubuntu server setup if need be)
3. Setup Nginx to act as a reverse proxy
   *  `sudo apt install nginx`
   *   Create a default.conf in `/etc/nginx/sites-enabled/`
   *   The default config will be at the bottom of this section
   *   `sudo systemctl enable nginx`
   *   `sudo service nginx restart`
   
  ```
    server {
        listen 8080;
        server_name sudo-cheese.org;
    
        # Honeypot listener
        location /honeypot/ {
            proxy_pass http://localhost:5000/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
```

## Installation and Setup For Local Running on an Ubuntu Server


1. Clone or download this repo
2. Setup a cloudflared tunnel following 
   * https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/
3. Install dependencies:
   * Python 2:
     * `sudo pip install -r requirements.txt`
     * `sudo pip install ollama`
   * Python 3:
     * `sudo pip3 install -r requirements.txt`
     * `sudo pip3 install ollama`
   *  `sudo curl -fsSL https://ollama.com/install.sh | sh`
   * `sudo apt install screen`
4. Create a new screen or TMUX and activate a virtual environment via this command:
   * `source .venv/bin/activate`
5. Within the llm directory containing the Modelfile:
   * `ollama create honeybot -f Modelfile`
7. Also within that same screen or TMUX Run HoneyHTTPD with:
   * Python 2 `sudo python2 start.py --config config.json`
   * Python 3 `sudo python3 start.py --config config.json`
8. Detach screen and setup cron jobs:
   * `Crontab -e` and insert the below, fill in locations accordingly
   * `0,30 * * * * /usr/bin/python3 /home/<user>/<path_to_project>/summarize_logs.py >> /home/<user>/<path_to_project>/logs/parser_cron.log 2>&1`
   * `2,32 * * * * /usr/bin/python3 /home/<user>/<path_to_project>/report.py >> /home/<user>/<path_to_project>/logs/report_cron.log 2>&1`

The server will start with the port, logging option, and server handlers defined in config.json.


Logs captured from running this server can be found in the logs/ directory locally or find the reports based on the logs at https://www.sudo-cheese.org/report.html


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


## Technologies and Platforms Used


* Python3
* HoneyHTTPD
* Ubuntu
* Ollama
* Qwen2.5



## Generating SSL certificates


```
openssl req -new -x509 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
```


From [here](https://gist.github.com/dergachev/7028596).

## Resources

The following are some general documentation to help out customizing the project, get your own server setup, and/or troubleshooting issues.
   * https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/
   * https://docs.ollama.com/quickstart
   * https://docs.ollama.com/modelfile
   * https://ubuntu.com/tutorials/install-ubuntu-server#1-overview
   * https://ollama.com/library/qwen2.5
   * https://ss64.com/bash/ 
   * https://ubuntu.com/server/docs/how-to/security/openssh-server/ 


## Contributing


Go at it! Open an issue, make a pull request, fork it, etc.


## License


This project is licensed under the Mozilla Public License, v2.0 (formerly GPL 3.0)



