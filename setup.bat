@echo off

REM Install required Python packages
pip install dnspython colorama pystyle requests speedtest-cli paramiko geopy PyMySQL psycopg2 pymongo folium ipwhois scapy

REM Open default web browser to Wireshark download page
start https://www.wireshark.org/download.html