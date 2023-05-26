#!/bin/sh

sudo kill $(ps aux | grep "python3 .*httpServer.py" | awk '{print $2}')
sudo kill $(ps aux | grep "python3 .*dnsServer.py" | awk '{print $2}')
sudo kill $(ps aux | grep "python3 .*client.py" | awk '{print $2}')
