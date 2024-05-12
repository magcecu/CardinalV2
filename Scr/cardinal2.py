import dns.resolver, dns.reversename
from random import choice
from colorama import init, Fore as cc
import os
import time
import webbrowser
import sys
import socket
from pystyle import Center
import platform
import subprocess
import requests
import platform
import ctypes
import ssl
import speedtest
from ftplib import FTP
import paramiko
import smtplib
import imaplib
import poplib
import psutil
import pyshark
from geopy.geocoders import Nominatim
import pymysql
import psycopg2
from pymongo import MongoClient
import folium
import threading
from ipwhois import IPWhois
from scapy.all import IP, ICMP, sr, sr1

init()
dr = DR = r = R = cc.LIGHTRED_EX 
g = G = cc.GREEN
r = R = cc.RED
b = B = cc.LIGHTBLUE_EX
m = M = cc.LIGHTMAGENTA_EX
c = C = cc.LIGHTCYAN_EX
y = Y = cc.LIGHTYELLOW_EX
w = W = cc.WHITE
b = B = cc.BLUE

s=0 
f=0 
imain=0

Greeting =Center.XCenter(Center.YCenter(f"""{m} 
  __          __  _                            _______                  _           
  \ \        / / | |                          |__   __|                | |          
   \ \  /\  / /__| | ___ ___  _ __ ___   ___     | |_ __ __ ___   _____| | ___ _ __ 
    \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \    | | '__/ _` \ \ / / _ \ |/ _ \ '__|
     \  /\  /  __/ | (_| (_) | | | | | |  __/    | | | | (_| |\ V /  __/ |  __/ |   
      \/  \/ \___|_|\___\___/|_| |_| |_|\___|    |_|_|  \__,_| \_/ \___|_|\___|_|   
                                                                      
                                                                                   {w}"""))

logocredit = Center.XCenter(Center.YCenter(f""" {y}
   _________    ____  ____  _____   _____    __ 
  / ____/   |  / __ \/ __ \/  _/ | / /   |  / / 
 / /   / /| | / /_/ / / / // //  |/ / /| | / /  
/ /___/ ___ |/ _, _/ /_/ // // /|  / ___ |/ /___
\____/_/  |_/_/ |_/_____/___/_/ |_/_/  |_/_____/
                                                
"""))
pinging = Center.XCenter(Center.YCenter(f""" {y}
    ____  _____   _____________   ________
   / __ \/  _/ | / / ____/  _/ | / / ____/
  / /_/ // //  |/ / / __ / //  |/ / / __  
 / ____// // /|  / /_/ // // /|  / /_/ /  
/_/   /___/_/ |_/\____/___/_/ |_/\____/   
            
                                       """))

Scanning = Center.XCenter(Center.YCenter(f""" {y}
   _____ _________    _   ___   _______   ________
  / ___// ____/   |  / | / / | / /  _/ | / / ____/
  \__ \/ /   / /| | /  |/ /  |/ // //  |/ / / __  
 ___/ / /___/ ___ |/ /|  / /|  // // /|  / /_/ /  
/____/\____/_/  |_/_/ |_/_/ |_/___/_/ |_/\____/   
 """))

Requesting = Center.XCenter(Center.YCenter(f""" {y}
    ____  __________  __  ________________________   ________
   / __ \/ ____/ __ \/ / / / ____/ ___/_  __/  _/ | / / ____/
  / /_/ / __/ / / / / / / / __/  \__ \ / /  / //  |/ / / __  
 / _, _/ /___/ /_/ / /_/ / /___ ___/ // / _/ // /|  / /_/ /  
/_/ |_/_____/\___\_\____/_____//____//_/ /___/_/ |_/\____/   
 """))

Dns = Center.XCenter(Center.YCenter(f""" {y}
    ____  _   _______
   / __ \/ | / / ___/
  / / / /  |/ /\__ \ 
 / /_/ / /|  /___/ / 
/_____/_/ |_//____/  
 """))
                                         
traceroutelogo = Center.XCenter(Center.YCenter(f""" {y}
   __________  ___   ________________  ____  __  ______________
 /_  __/ __ \/   | / ____/ ____/ __ \/ __ \/ / / /_  __/ ____/
  / / / /_/ / /| |/ /   / __/ / /_/ / / / / / / / / / / __/   
 / / / _, _/ ___ / /___/ /___/ _, _/ /_/ / /_/ / / / / /___   
/_/ /_/ |_/_/  |_\____/_____/_/ |_|\____/\____/ /_/ /_____/   
 """))

whoislogo = Center.XCenter(Center.YCenter(f""" {y}
 _       ____  ______  _________
| |     / / / / / __ \/  _/ ___/
| | /| / / /_/ / / / // / \__ \ 
| |/ |/ / __  / /_/ // / ___/ / 
|__/|__/_/ /_/\____/___//____/  
 """))

ssllogo =  Center.XCenter(Center.YCenter(f""" {y}
   __________ __         __              __  
  / ___/ ___// /   _____/ /_  ___  _____/ /__
  \__ \\__ \/ /   / ___/ __ \/ _ \/ ___/ //_/
 ___/ /__/ / /___/ /__/ / / /  __/ /__/ ,<   
/____/____/_____/\___/_/ /_/\___/\___/_/|_|  
 """))

bandwlogo = Center.XCenter(Center.YCenter(f""" {y}
    ____  ___    _   ______ _       __________  ________  __
   / __ )/   |  / | / / __ \ |     / /  _/ __ \/_  __/ / / /
  / __  / /| | /  |/ / / / / | /| / // // / / / / / / /_/ / 
 / /_/ / ___ |/ /|  / /_/ /| |/ |/ // // /_/ / / / / __  /  
/_____/_/  |_/_/ |_/_____/ |__/|__/___/_____/ /_/ /_/ /_/   
 """))

ftplogo = Center.XCenter(Center.YCenter(f""" {y}
    __________________
   / ____/_  __/ __  /
  / /_    / / / /_/ /
 / __/   / / / ____/ 
/_/     /_/ /_/      
 """))

sshlogo = Center.XCenter(Center.YCenter(f""" {y}
   __________ __  __
  / ___/ ___// / / /
  \__ \\__ \/ /_/ / 
 ___/ /__/ / __  /  
/____/____/_/ /_/   
 """))

emaillogo = Center.XCenter(Center.YCenter(f""" {y}
    ________  ______    ______  _______________________
   / ____/  |/  /   |  /  _/ / /_  __/ ____/ ___/_  __/
  / __/ / /|_/ / /| |  / // /   / / / __/  \__ \ / /   
 / /___/ /  / / ___ |_/ // /___/ / / /___ ___/ // /    
/_____/_/  /_/_/  |_/___/_____/_/ /_____//____//_/     
 """))

geologo = Center.XCenter(Center.YCenter(f""" {y}
    ________________  __    ____  _________  __________  ____ 
  / ____/ ____/ __ \/ /   / __ \/ ____/   |/_  __/ __ \/ __  /
 / / __/ __/ / / / / /   / / / / /   / /| | / / / / / / /_/ /
/ /_/ / /___/ /_/ / /___/ /_/ / /___/ ___ |/ / / /_/ / _, _/ 
\____/_____/\____/_____/\____/\____/_/  |_/_/  \____/_/ |_|  
 """))

infologo = Center.XCenter(Center.YCenter(f""" {y}
   __________  __    __    _______________________   ________
  / ____/ __ \/ /   / /   / ____/ ____/_  __/  _/ | / / ____/
 / /   / / / / /   / /   / __/ / /     / /  / //  |/ / / __  
/ /___/ /_/ / /___/ /___/ /___/ /___  / / _/ // /|  / /_/ /  
\____/\____/_____/_____/_____/\____/ /_/ /___/_/ |_/\____/   
 """))

analogo = Center.XCenter(Center.YCenter(f""" {y}
    ___    _   _____    ____  _______   ____________ 
   /   |  / | / /   |  / /\ \/ /__  /  / ____/ __  /
  / /| | /  |/ / /| | / /  \  /  / /  / __/ / /_/ /
 / ___ |/ /|  / ___ |/ /___/ /  / /__/ /___/ _, _/ 
/_/  |_/_/ |_/_/  |_/_____/_/  /____/_____/_/ |_|  
 """))

datalogo = Center.XCenter(Center.YCenter(f""" {y}
   __________  _   ___   _________________________   ________
  / ____/ __ \/ | / / | / / ____/ ____/_  __/  _/ | / / ____/
 / /   / / / /  |/ /  |/ / __/ / /     / /  / //  |/ / / __  
/ /___/ /_/ / /|  / /|  / /___/ /___  / / _/ // /|  / /_/ /  
\____/\____/_/ |_/_/ |_/_____/\____/ /_/ /___/_/ |_/\____/   
 """))

ddoslogo = Center.XCenter(Center.YCenter(f""" {y}
   ____ _    ____________  __    ____  ___    ____  _____   ________
  / __ \ |  / / ____/ __ \/ /   / __ \/   |  / __ \/  _/ | / / ____/
 / / / / | / / __/ / /_/ / /   / / / / /| | / / / // //  |/ / / __  
/ /_/ /| |/ / /___/ _, _/ /___/ /_/ / ___ |/ /_/ // // /|  / /_/ /  
\____/ |___/_____/_/ |_/_____/\____/_/  |_/_____/___/_/ |_/\____/   
 """))

logomain = f""" {y}                                                                                                                               
       _..._                                                                         
    .-'_..._''.                      _______                                   .---. 
  .' .'      '.\                     \  ___ `'.    .--.    _..._               |   | 
 / .'                                 ' |--.\  \   |__|  .'     '.             |   | 
. '                         .-,.--.   | |    \  '  .--. .   .-.   .            |   | 
| |                  __     |  .-. |  | |     |  ' |  | |  '   '  |     __     |   | 
| |               .:--.'.   | |  | |  | |     |  | |  | |  |   |  |  .:--.'.   |   | 
. '              / |   \ |  | |  | |  | |     ' .' |  | |  |   |  | / |   \ |  |   | 
 \ '.          . `" __ | |  | |  '-   | |___.' /'  |  | |  |   |  | `" __ | |  |   | 
  '. `._____.-'/  .'.''| |  | |      /_______.'/   |__| |  |   |  |  .'.''| |  |   | 
    `-.______ /  / /   | |_ | |      \_______|/         |  |   |  | / /   | |_ '---' V2
             `   \ \._,\ '/ |_|                         |  |   |  | \ \._,\ '/         by MagCecu
                  `--'  `"                              '--'   '--'  `--'  `"                  {r}
"""
logo_width = 100
logo_height = 32

options = f"""
   {w}-[{r}1{w}]-{r} Ping Test                  {w}-[{r}11{w}]-{r} FTP Connectivity Test
   {w}-[{r}2{w}]-{r} Port Scanner               {w}-[{r}12{w}]-{r} Email Server Test(SMTP, IMAP, POP3)
   {w}-[{r}3{w}]-{r} HTTP/HTTPS Request         {w}-[{r}13{w}]-{r} IP Geolocation
   {w}-[{r}4{w}]-{r} DNS Lookup                 {w}-[{r}14{w}]-{r} Server Information(PATH required)
   {w}-[{r}5{w}]-{r} Reverce DNS Lookup         {w}-[{r}15{w}]-{r} Custom Scripting
   {w}-[{r}6{w}]-{r} Traceroute                 {w}-[{r}16{w}]-{r} Traffic Analysis
   {w}-[{r}7{w}]-{r} WHOIS Lookup               {w}-[{r}17{w}]-{r} Database Connectivity Test
   {w}-[{r}8{w}]-{r} SSL/TLS Certificate Check  {w}-[{r}18{w}]-{r} Stress Test (DDoS)
   {w}-[{r}9{w}]-{r} Bandwidth Test             {w}-[{r}19{w}]-{r} Credits
   {w}-[{r}10{w}]-{r} SSH Connectivity Test     {w}-[{r}20{w}]-{r} Exit
"""
def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
    
def greeting():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Greeting)
    time.sleep(2)
    os.system('cls' if os.name == 'nt' else 'clear')

def tmsize():
    try:
        columns, rows = os.get_terminal_size()
        return rows, columns
    except OSError:
        # if os.get_terminal_size() => default size
        return 25, 80  

def expand(logo_width, logo_height):
    terminal_rows, terminal_columns = tmsize()
    while terminal_rows < logo_height or terminal_columns < logo_width:
        os.system('mode con: cols={} lines={}'.format(
            max(terminal_columns, logo_width), 
            max(terminal_rows, logo_height)
        ))
        terminal_rows, terminal_columns = tmsize()

def ping_server(ip_address):
    global s, f   
    try:
        socket.gethostbyname(ip_address)
        print(f"{ip_address} is reachable.")
        s += 1
    except socket.error as e:
        print(f"{ip_address} is not reachable: {e}")
        f += 1
        
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        
        result = s.connect_ex((ip, port))
        if result == 0:
            return port
        else:
            return None
        
        s.close()
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return None
        
def scan_ip(ip, start_port, end_port):
    open_ports= []
    print(Scanning)
    print(Center.XCenter(ip))
    for port in range(start_port, end_port + 1):
        open_port = scan_port(ip, port)
        if open_port:
            open_ports.append(open_port)
    return open_ports

def test_https(ip):
    try:
        url = f"https://{ip}"
        response = requests.get(url)
        if response.status_code == 200:
            return {
                "status_code": response.status_code,
                "headers": response.headers,
                "server": response.headers.get("Server"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
                "response_body": response.text[:200]  
            }
        else:
            return None
    except Exception as e:
        print(f"Error testing HTTPS: {e}")
        return None
    
def test_http(ip):
    try:
        url = f"http://{ip}"
        response = requests.get(url)
        if response.status_code == 200:
            return {
                "status_code": response.status_code,
                "headers": response.headers,
                "server": response.headers.get("Server"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
                "response_body": response.text[:200]
            }
        else:
            return None
    except Exception as e:
        print(f"Error testing HTTP: {e}")
        return None
    
def save_to_file(data, filename):
    with open(filename, 'w') as f:
        for item in data:
            f.write(f"{'-'*20}\n")
            if 'url' in item:
                f.write(f"URL: {item['url']}\n")
            f.write(f"Status Code: {item.get('status_code', 'N/A')}\n")
            f.write("Headers:\n")
            headers = item.get('headers', {})
            for key, value in headers.items():
                f.write(f"\t{key}: {value}\n")
            f.write(f"Server: {item.get('server', 'N/A')}\n")
            f.write(f"Content Type: {item.get('content_type', 'N/A')}\n")
            f.write(f"Content Length: {item.get('content_length', 'N/A')}\n")
            f.write(f"Response Body (first 200 chars): {item.get('response_body', 'N/A')}\n\n")
            
def open_text_file(filename):
    try:
        abs_path = os.path.abspath(filename)
        system = platform.system()
        if system == "Linux":
            subprocess.run(['xdg-open', abs_path])
        elif system == "Darwin":  
            subprocess.run(['open', abs_path])
        elif system == "Windows":
            subprocess.run(['start', '', abs_path], shell=True)
        else:
            print("Unsupported operating system.")
    except Exception as e:
        print(f"Error opening file: {e}")
        
def dns_lookup(hostname):
    try:
        canonical_hostname, alias_list, ip_address_list = socket.gethostbyname_ex(hostname)
        print(f"Canonical hostname: {canonical_hostname}")
        print(f"Aliases: {alias_list}")
        print(f"IP addresses: {ip_address_list}")
    except socket.error as e:
        print(f"Error: {e}")
        
def reverse_dns_lookup(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        print(f"The hostname for IP address {ip_address} is {hostname}")
    except socket.herror as e:
        print(f"Error: {e}")
        
def traceroute(target, max_hops=30):
    ttl = 1
    while True:
        pkt = IP(dst=target, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)
        if reply is None:
            print(f"{ttl}. *")
        elif reply.type == 11: 
            print(f"{ttl}. {reply.src}")
        elif reply.type == 0: 
            print(f"{ttl}. {reply.src} (Destination Reached)")
            break
        ttl += 1
        if ttl > max_hops:
            print("Max hops reached.")
            break

def ip_whois_lookup(ip_address):
    try:
        
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        
        print("IP Address:", ip_address)
        print("ASN:", result['asn'])
        print("ASN CIDR:", result['asn_cidr'])
        print("ASN Country Code:", result['asn_country_code'])
        print("ASN Description:", result['asn_description'])
        print("Network Name:", result['network']['name'])
        print("Network Handle:", result['network']['handle'])
        print("Network Start Address:", result['network']['start_address'])
        print("Network End Address:", result['network']['end_address'])
        print("Network CIDR:", result['network']['cidr'])
        print("Network Type:", result['network']['type'])
        print("Network Country:", result['network']['country'])
        
    except Exception as e:
        print(f"Error performing IP WHOIS lookup: {e}")
        
def ssl_certificate_check(hostname, port=443):
    try:
        
        sock = socket.create_connection((hostname, port))
        
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            
            cert = ssock.getpeercert()
            
            print("Subject:", cert.get("subject"))
            print("Issuer:", cert.get("issuer"))
            print("Expiration Date:", cert.get("notAfter"))
            print("Start Date:", cert.get("notBefore"))
            print("Serial Number:", cert.get("serialNumber"))
            print("Signature Algorithm:", cert.get("signatureAlgorithm"))
            print("Public Key Algorithm:", cert.get("subjectPublicKeyAlgorithm"))
             
    except Exception as e:
        print(f"Error performing SSL/TLS certificate check: {e}")
        
def bandwidth_test(server_id=None):
    try:
        
        st = speedtest.Speedtest()
        
        if server_id is None:
            st.get_best_server()
        else:
            st.get_servers([server_id])
        
        download_speed = st.download()
        print("")
        print(f"Download Speed: {download_speed / 1_000_000:.2f} Mbps")
        
        upload_speed = st.upload()
        print(f"Upload Speed: {upload_speed / 1_000_000:.2f} Mbps")
    
    except Exception as e:
        print(f"Error performing bandwidth test: {e}")
        
def ftp_connectivity_test(host, username=None, password=None):
    try:

        ftp = FTP()
        ftp.connect(host)

        if username and password:
            ftp.login(username, password)

        print("FTP connectivity test successful. Connected to", host)

        files = ftp.nlst()
        print("Files on the server:", files)

        # Optionally transfer a file
        # with open('local_file.txt', 'rb') as local_file:
        #     ftp.storbinary('STOR remote_file.txt', local_file)

        ftp.quit()

    except Exception as e:
        print(f"Error during FTP connectivity test: {e}")
        
def ssh_connectivity_test(hostname, username, password, port):
    try:

        ssh_client = paramiko.SSHClient()

        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh_client.connect(hostname, port=port, username=username, password=password)

        print("SSH connectivity test successful. Connected to", hostname)

        # Optionally, execute a command on the server
        # stdin, stdout, stderr = ssh_client.exec_command('ls -l')
        # print("Server response:", stdout.read().decode())

        ssh_client.close()

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your username and password.")
    except paramiko.SSHException as e:
        print(f"SSH error: {e}")
    except Exception as e:
        print(f"Error during SSH connectivity test: {e}")
        
def smtp_connectivity_test(smtp_server, smtp_port):
    try:

        server = smtplib.SMTP(smtp_server, smtp_port)
        print("SMTP connectivity test successful. Connected to", smtp_server)
        server.quit()

    except Exception as e:
        print(f"Error during SMTP connectivity test: {e}")
        
def imap_connectivity_test(imap_server, imap_port):
    try:

        server = imaplib.IMAP4_SSL(imap_server, imap_port)
        print("IMAP connectivity test successful. Connected to", imap_server)
        server.logout()

    except Exception as e:
        print(f"Error during IMAP connectivity test: {e}")
        
def pop3_connectivity_test(pop3_server, pop3_port):
    try:

        server = poplib.POP3(pop3_server, pop3_port)
        print("POP3 connectivity test successful. Connected to", pop3_server)
        server.quit()

    except Exception as e:
        print(f"Error during POP3 connectivity test: {e}")

def get_ip_location(ip_address):
    try:
 
        response = requests.get(f"http://ipinfo.io/{ip_address}/json")
        data = response.json()

        latitude, longitude = data.get('loc', '').split(',')
        return float(latitude), float(longitude)
    except Exception as e:
        print(f"Error retrieving IP location: {e}")
        return None, None

def generate_map(ip_address, latitude, longitude):
    map = folium.Map(location=[latitude, longitude], zoom_start=10)

    folium.Marker([latitude, longitude], popup=ip_address).add_to(map)
    
    map_dir = "ipmaps"
    if not os.path.exists(map_dir):
        os.makedirs(map_dir)
    map_file = os.path.join(map_dir, f"{ip_address}.html")
    map.save(map_file)
    print("Map generated and saved as", map_file)

    webbrowser.open("file://" + os.path.abspath(map_file))    

def get_operating_system():
    return platform.platform()

def get_kernel_version():
    return platform.uname().version

def get_server_software():
    try:

        # For example, for Apache:
        # output = subprocess.check_output(["apache2", "-v"])
        # For Nginx:
        # output = subprocess.check_output(["nginx", "-v"])
        output = subprocess.check_output(["httpd", "-v"])  
        return output.decode().splitlines()[0]
    except subprocess.CalledProcessError as e:
        return "Server software information not available"

def get_uptime():
    try:
        output = subprocess.check_output(["uptime"])
        return output.decode().strip()
    except subprocess.CalledProcessError as e:
        return "Uptime information not available"

def get_cpu_info():
    try:
        output = subprocess.check_output(["lscpu"])
        return output.decode().strip()
    except subprocess.CalledProcessError as e:
        return "CPU information not available"

def get_memory_info():
    try:
        output = subprocess.check_output(["free", "-h"])
        return output.decode().strip()
    except subprocess.CalledProcessError as e:
        return "Memory information not available"
    
def execute_custom_script_or_command(script_or_command):
    try:
        output = subprocess.check_output(script_or_command, shell=True)
        return output.decode().strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing script or command: {e}"
    
def get_interface_names():
    # Get a list of network interface names
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def perform_traffic_analysis(network_interface):
    def print_packet_info(packet):
        print("Packet Details:")
        print("-----------------------------")
        print(f"Time: {packet.sniff_time}")
        print(f"Source IP: {packet.ip.src}")
        print(f"Destination IP: {packet.ip.dst}")
        print(f"Protocol: {packet.transport_layer}")
        print(f"Length: {packet.length} bytes")
        print(f"Info: {packet.transport_layer} {packet.ip.src}:{packet[packet.transport_layer].srcport} -> {packet.ip.dst}:{packet[packet.transport_layer].dstport}")

    try:
        # Start capturing packets
        capture = pyshark.LiveCapture(interface=network_interface)

        capture.apply_on_packets(print_packet_info)

    except pyshark.capture.capture.TSharkVersionException:
        print(f"Error: TShark (part of Wireshark) is not installed or not in the PATH. Please install Wireshark.")
    except Exception as e:
        print(f"Error: {e}")
        exitv=input("Continue Despite it?? Press Enter or exit(hit any key then press Enter)...")
        if exitv=="":
            perform_traffic_analysis(network_interface)
        else:
            main()

def test_mysql_connection(host, user, password, database):
    try:
        conn = pymysql.connect(host=host, user=user, password=password, database=database)
        cursor = conn.cursor()

        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print("MySQL Server version:", version[0])

        cursor.close()
        conn.close()
        print("MySQL connection successful")
    except pymysql.Error as e:
        print("Error connecting to MySQL:", e)

def test_postgresql_connection(host, port, user, password, database):
    try:
        conn = psycopg2.connect(host=host, port=port, user=user, password=password, database=database)
        cursor = conn.cursor()

        cursor.execute("SELECT version()")
        version = cursor.fetchone()
        print("PostgreSQL Server version:", version[0])

        cursor.close()
        conn.close()
        print("PostgreSQL connection successful")
    except psycopg2.Error as e:
        print("Error connecting to PostgreSQL:", e)

def test_mongodb_connection(host, port, database):
    try:
        client = MongoClient(host, port)
        db = client[database]

        collections = db.list_collection_names()
        print("MongoDB Collections:", collections)

        print("MongoDB connection successful")
    except Exception as e:
        print("Error connecting to MongoDB:", e)
        
def send_requests(server_url, num_requests):
    try:
        response = requests.get(server_url)
        if response.status_code == 200:
            print("Request successful")
        else:
            print("Request failed:", response.status_code)
    except Exception as e:
        print("Exception occurred:", e)
        
def stress_test(server_url, num_threads, num_requests_per_thread):
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_requests, args=(server_url, num_requests_per_thread))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
def main():
    os.system("title CardinalV2 || Made By MagCecu")
    os.system('cls' if os.name == 'nt' else 'clear')
    expand(logo_width, logo_height)
    print(logomain)
    print(options)
    num = input(">>> ")
    os.system('cls' if os.name == 'nt' else 'clear')
    if num == "1":
        print(logomain)
        ip_address = input("Ip Address>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(pinging)
        time.sleep(0.3)
        i=0
        while True:
            ping_server(ip_address)
            i=i+1
            if i==20:
                break
        print("")
        print("Successful pings: " + str(s))
        print("Unsuccessful pings " + str(f))
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "2":
        print(logomain)
        target_ip = input("Enter target IP address>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))
        os.system('cls' if os.name == 'nt' else 'clear')
        open_ports = scan_ip(target_ip, start_port, end_port)
        if open_ports:
            print("Open ports:")
        for port in open_ports:
            print(port)
        else:
            print("No open ports found.")
        input("Press Enter To Exit...")
        os.system('cls' if os.name == 'nt' else 'clear')
        main()
    
    if num == "3":
        print(logomain)
        target_ip = input("Enter target IP address>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Requesting)
        print(Center.XCenter(target_ip))
        time.sleep(1.5)
        
        http_info = test_http(target_ip)
        https_info = test_https(target_ip)
        filename=f"HTTPHTTPS req\\{target_ip}.txt"

        results = []
        if http_info:
            print("HTTP service is running on the target IP.")
            results.append(http_info)

        if https_info:
            print("HTTPS service is running on the target IP.")
            results.append(https_info)
        
        if results:
            save_to_file(results, filename)
            print("Results saved to service_info.txt")
        else:
            print("No HTTP or HTTPS services found on the target IP.")
            
        open_text_file(filename)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "4":
        print(logomain)
        hostname = input("Enter the hostname>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Dns)
        print(Center.XCenter(hostname))
        time.sleep(1.5)
        dns_lookup(hostname)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "5":
        print(logomain)
        ip_address = input("Enter the IP address>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Dns)
        print(Center.XCenter(ip_address))
        time.sleep(1.5)
        reverse_dns_lookup(ip_address)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "6":
        print(logomain)
        target = input("Enter the target IP address or domain name>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(traceroutelogo)
        print(Center.XCenter(target))
        time.sleep(1.5)
        traceroute(target)
        print("")
        input("Press Enter To Exit...")
        main()
    
    if num == "7":
        print(logomain)
        target = input("Enter the IP address>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(whoislogo)
        print(Center.XCenter(target))
        time.sleep(1.5)
        if '.' + '.' in target:
            ip_whois_lookup(target)
        else:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(Center.XCenter(Center.YCenter("!Not a valid IP!")))
            time.sleep(1)
            main()
            
    if num == "8":
        print(logomain)
        target = input("Enter the domain name>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(ssllogo)
        print(Center.XCenter(target))
        time.sleep(1.5)
        print("")
        ssl_certificate_check(target)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "9":
        print(logomain)
        idb = input("Enter serverID (leave bank for default)>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(bandwlogo)
        print(Center.XCenter("...Testing..."))
        print("")
        if idb == "":
            idb = None
        bandwidth_test(server_id=idb)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "10":
        print(logomain)
        hostname = input("Enter FTP server hostname>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        print("!Leave blank if none!")
        username = input("Username>>> ")
        password = input("Password>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        port = input("Port(Default=22)>>> ")
        if username == "":
            username = None
        if password == "":
            password = None
        if port == "":
            port = 22
        
        print(sshlogo)
        print(Center.XCenter(hostname))
        print("")
        ssh_connectivity_test(hostname, username, password, port)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "11":
        print(logomain)
        hostname = input("Enter FTP server hostname>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        print("!Leave blank if none!")
        username = input("Username>>> ")
        password = input("Password>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        
        if username == "":
            username = None
        if password == "":
            password = None
        
        print(ftplogo)
        print(Center.XCenter(hostname))
        print("")
        ftp_connectivity_test(hostname, username, password)
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "12":
        one = 1
        two = 1
        three = 1
        print(logomain)
        print("!Leave blank if you want to skip this test!")
        smtp_server = input("Enter SMTP server hostname or IP address>>> ")
        smtp_port = int(input("Enter SMTP port (usually 587 for TLS/STARTTLS or 25 for non-encrypted)>>> "))
        os.system('cls' if os.name == 'nt' else 'clear')
        
        if smtp_server=="":
            one=one-1
        if smtp_port=="":
            one=one-1
            
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        print("!Leave blank if you want to skip this test!")
        imap_server = input("Enter IMAP server hostname or IP address>>> ")
        imap_port = int(input("Enter IMAP port (usually 993 for SSL/TLS)>>> "))
        os.system('cls' if os.name == 'nt' else 'clear')
        
        if imap_server=="":
            two=two-1
        if imap_port=="":
            two=two-1
        
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        print("!Leave blank if you want to skip this test!")
        pop3_server = input("Enter POP3 server hostname or IP address>>> ")
        pop3_port = int(input("Enter POP3 port (usually 995 for SSL/TLS)>>> "))
        os.system('cls' if os.name == 'nt' else 'clear')
        
        if pop3_server=="":
            three=three-1
        if pop3_port=="":
            three=three-1
            
        print(emaillogo)
        print("")
        if one==1:
            if two==1:
                if three==1:
                    smtp_connectivity_test(smtp_server, smtp_port)
                    imap_connectivity_test(imap_server, imap_port)
                    pop3_connectivity_test(pop3_server, pop3_port)
                else:
                    smtp_connectivity_test(smtp_server, smtp_port)
                    imap_connectivity_test(imap_server, imap_port)
            else:
                if three==1:
                    smtp_connectivity_test(smtp_server, smtp_port)
                    pop3_connectivity_test(pop3_server, pop3_port)
                else:
                    smtp_connectivity_test(smtp_server, smtp_port)
        else:
            if two==1:
                if three==1:
                    imap_connectivity_test(imap_server, imap_port)
                    pop3_connectivity_test(pop3_server, pop3_port)
                else:
                    imap_connectivity_test(imap_server, imap_port)
            else:
                if three==1:
                    pop3_connectivity_test(pop3_server, pop3_port) 
        print("")
        input("Press Enter To Exit...")
        main()
    
    if num == "13":
        print(logomain)
        ip_address = input("Enter the target IP address>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(geologo)
        print(Center.XCenter(ip_address))
        #time.sleep(1.5)
        latitude, longitude = get_ip_location(ip_address)
        if latitude is not None and longitude is not None:
            generate_map(ip_address, latitude, longitude)
        else:
            print("Unexpected error")
        print("")
        input("Press Enter To Exit...")
        main()
    
    if num == "14":
        operating_system = get_operating_system()
        kernel_version = get_kernel_version()
        server_software = get_server_software()
        uptime = get_uptime()
        cpu_info = get_cpu_info()
        memory_info = get_memory_info()
        print(infologo)
        time.sleep(1.5)
        print("Operating System:", operating_system)
        print("Kernel Version:", kernel_version)
        print("Server Software:", server_software)
        print("Uptime:", uptime)
        print("CPU Info:", cpu_info)
        print("Memory Info:", memory_info)
        print()
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == '15':
        print(logocredit)
        print(Center.XCenter("/exit to exit shell"))
        print()
        while True:
            script_or_command = input("Cardinal Shell>>> ")
            if script_or_command == '/exit':
                break
            else:
                result = execute_custom_script_or_command(script_or_command)
                print("Result:", result)
        main()
        
    if num == "16":
        print(logomain)
        network_interface = input("Network Name(Ethernet0 for example)>>> ")
                
        os.system('cls' if os.name == 'nt' else 'clear')
        print(analogo)
        print(Center.XCenter("CARDINAL"))

        available_interfaces = get_interface_names()

        if network_interface in available_interfaces:
            perform_traffic_analysis(network_interface)
        else:
            print(f"Error: Interface {network_interface} does not exist.")
        print("")
        input("Press Enter To Exit...")
        main()
        
    if num == "17":
        print(logomain)
        print("""
              [1] MySQL [2] PostgreSQL [3] MongoDB""")
        num2=input(">>> ")
        if num2 == "1":
            os.system('cls' if os.name == 'nt' else 'clear')
            print(logomain)
            mysql_host = input("Enter MySQL host (default: localhost): ") or "localhost"
            mysql_port = input("Enter MySQL port (default: 3306): ") or "3306"
            mysql_user = input("Enter MySQL user: ")
            mysql_password = input("Enter MySQL password: ")
            mysql_database = input("Enter MySQL database: ")
            os.system('cls' if os.name == 'nt' else 'clear')
            print(datalogo)
            time.sleep(1)
            test_mysql_connection(mysql_host, int(mysql_port), mysql_user, mysql_password, mysql_database)
            input("Press Enter to exit...")
            main()
            
        if num2 == "2":
            os.system('cls' if os.name == 'nt' else 'clear')
            print(logomain)
            postgresql_host = input("Enter PostgreSQL host (default: localhost): ") or "localhost"
            postgresql_port = input("Enter PostgreSQL port (default: 5432): ") or "5432"
            postgresql_user = input("Enter PostgreSQL user: ")
            postgresql_password = input("Enter PostgreSQL password: ")
            postgresql_database = input("Enter PostgreSQL database: ")
            os.system('cls' if os.name == 'nt' else 'clear')
            print(datalogo)
            time.sleep(1)
            test_postgresql_connection(postgresql_host, postgresql_port, postgresql_user, postgresql_password, postgresql_database)
            input("Press Enter to exit...")
            main()
            
        if num2 == "3":
            os.system('cls' if os.name == 'nt' else 'clear')
            print(logomain)
            mongodb_host = input("Enter MongoDB host (default: localhost): ") or "localhost"
            mongodb_port = input("Enter MongoDB port (default: 27017): ") or 27017
            mongodb_database = input("Enter MongoDB database: ")
            os.system('cls' if os.name == 'nt' else 'clear')
            print(datalogo)
            time.sleep(1)
            test_mongodb_connection(mongodb_host, int(mongodb_port), mongodb_database)
            print("")
            input("Press Enter to exit...")
            main()
    
    if num == "18":
        print(logomain)
        server_url=input("Server URL>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(logomain)
        num_threads=input("Select the number of threads>>> ")
        num_requests_per_thread=input("Select the number of requests per thread>>> ")
        os.system('cls' if os.name == 'nt' else 'clear')
        print(ddoslogo)
        stress_test(server_url, num_threads, num_requests_per_thread)
        print("")
        input("Press Enter to exit...")
        main()
        
    if num == "19":
        print(logocredit)
        time.sleep(0.7)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Center.XCenter(Center.YCenter("Made By MagCecu")))
        time.sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Center.XCenter(Center.YCenter("Discord: magcecu")))
        time.sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Center.XCenter(Center.YCenter("Telegram: OneandOnlyMag")))
        time.sleep(1)
        os.system('cls' if os.name == 'nt' else 'clear')
        print(Center.XCenter(Center.YCenter("Distributed by The Mag Market")))
        time.sleep(0.5)
        os.system('cls' if os.name == 'nt' else 'clear')
    if num == "20":
        exit()
        
    else:
        main()

greeting()
if ctypes.windll.shell32.IsUserAnAdmin() == 1:
    main()
else:
    print(Center.XCenter(Center.YCenter(f"{r}!PLease Accept Admin!")))
    time.sleep(1)
    run_as_admin()
    exit()