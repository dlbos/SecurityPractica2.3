from nmap import *
import socket
import sys
import argparse
import pyfiglet
from scapy.all import *
def main():
   menu()

def menu():
    print()

    choice = input("""
      A: Portscanner
      B: Ip Scanner
      C: Mac Adress Scanner
      Q: Exit

      Please enter your choice: """)

    if choice == "A" or choice =="a":
        portscanner()
    elif choice == "B" or choice =="b":
        ipscanner()
    elif choice == "C" or choice =="c":
        macscan()
    elif choice == "D" or choice =="d":
        osscanner()
    elif choice=="Q" or choice=="q":
        sys.exit
    else:
        print("You must only select either A, B or C.")
        print("Please try again")
        menu()
# port scanner
def portscanner():
   import sys
   import socket
   from datetime import datetime
   
   ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
   print(ascii_banner)
   
   # Defining a target
   if len(sys.argv) == 2:
      
      # translate hostname to IPv4
      target = socket.gethostbyname(sys.argv[1])
   else:
      print("Invalid amount of Argument")
   
   # Add Banner
   print("-" * 50)
   print("Scanning Target: " + target)
   print("Scanning started at:" + str(datetime.now()))
   print("-" * 50)
   
   try:
      
      # will scan ports between 1 to 65,535
      for port in range(1,65535):
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
         socket.setdefaulttimeout(1)
            
         # returns an error indicator
         result = s.connect_ex((target,port))
         if result ==0:
               print("Port {} is open".format(port))
         s.close()
            
   except KeyboardInterrupt:
         print("\n Exiting Program !!!!")
         sys.exit()
   except socket.gaierror:
         print("\n Hostname Could Not Be Resolved !!!!")
         sys.exit()
   except socket.error:
         print("\ Server not responding !!!!")
         sys.exit()

   # import random

   # # Define end host and TCP port range
   # net = input("Enter the IP address: ")
   # net1 = net.split('.')
   # a = '.'

   # net2 = net1[0] + a + net1[1] + a + net1[2] + a
   # st1 = int(input("Enter the Starting Number: "))
   # en1 = int(input("Enter the Last Number: "))
   # en1 = en1 + 1


   # for ip in range(st1,en1):
   #    addr = net2 + str(ip)
   #    host = addr
   #    port_range = [22, 23, 80, 443, 3389]

   #    # Send SYN with random Src Port for each Dst port
   #    for dst_port in port_range:
   #       src_port = random.randint(1025,65534)
   #       resp = sr1(
   #          IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
   #          verbose=0,
   #       )

   #       if resp is None:
   #          print(f"{host}:{dst_port} is filtered (silently dropped).")

   #       elif(resp.haslayer(TCP)):
   #          if(resp.getlayer(TCP).flags == 0x12):
   #                # Send a gratuitous RST to close the connection
   #                send_rst = sr(
   #                   IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
   #                   timeout=1,
   #                   verbose=0,
   #                )
   #                print(f"{host}:{dst_port} is open.")

   #          elif (resp.getlayer(TCP).flags == 0x14):
   #                print(f"{host}:{dst_port} is closed.")

   #       elif(resp.haslayer(ICMP)):
   #          if(
   #                int(resp.getlayer(ICMP).type) == 3 and
   #                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
   #          ):
   #                print(f"{host}:{dst_port} is filtered (silently dropped).")

def osscanner():
   nm = nmap.PortScanner()
   machine = nm.scan('<hostIP>', arguments='-O')
   print(machine['scan']['<hostIP>']['osmatch'][0]['osclass'][0]['osfamily'])

def hostnamescanner():
   nm = nmap.PortScanner()
   nm.scan(hosts='192.168.0.1/24', arguments='-n -sP -PE -PA21,23,80,3389')

   hosts_list = [(x, nm[x]['status']['state'],socket.gethostbyaddr(x)[0]) for x in nm.all_hosts() if socket.gethostbyaddr(x)[0]]
   for host, status,name in hosts_list:
      print('{0}:{1}:{2}'.format(host, status,name))



def macscan():
   ascii_banner = pyfiglet.figlet_format("MAC ADRESS SCANNER")
   print(ascii_banner)
   target_ip = "192.168.0.1/24"
   # IP Address for the destination
   # create ARP packet
   arp = ARP(pdst=target_ip)
   # create the Ether broadcast packet
   # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
   ether = Ether(dst="ff:ff:ff:ff:ff:ff")
   # stack them
   packet = ether/arp

   result = srp(packet, timeout=3, verbose=0)[0]

   # a list of clients, we will fill this in the upcoming loop
   clients = []

   for sent, received in result:
      # for each response, append ip and mac address to `clients` list
      clients.append({'ip': received.psrc, 'mac': received.hwsrc})

   # print clients
   print("Available devices in the network:")
   print("IP" + " "*18+"MAC")
   for client in clients:
      print("{:16}    {}".format(client['ip'], client['mac']))

# def portscanner():
#    # Port Scanner -----------------------------------------------------------------------------------------
#    import socket
#    from datetime import datetime
#    net = input("Enter the IP address: ")
#    net1 = net.split('.')
#    a = '.'

#    net2 = net1[0] + a + net1[1] + a + net1[2] + a
#    st1 = int(input("Enter the Starting Number: "))
#    en1 = int(input("Enter the Last Number: "))
#    en1 = en1 + 1
#    t1 = datetime.now()

#    def scan(addr):
#       s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#       socket.setdefaulttimeout(1)
#       result = s.connect_ex((addr,135))
#       if result == 0:
#          return 1
#       else :
#          return 0

#    def run1():
#       for ip in range(st1,en1):
#          addr = net2 + str(ip)
#          if (scan(addr)):
#             print (addr , "is live")
         
#    run1()
#    t2 = datetime.now()
#    total = t2 - t1
#    print ("Scanning completed in: " , total)

# IP Scanner -------------------------------------------------------------------------------------------
def ipscanner():
   import socket
   import time
   import threading

   from queue import Queue
   socket.setdefaulttimeout(0.25)
   print_lock = threading.Lock()

   target = input('Enter the host to be scanned: ')
   t_IP = socket.gethostbyname(target)
   print ('Starting scan on host: ', t_IP)

   def portscan(port):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      try:
         con = s.connect((t_IP, port))
         with print_lock:
            print(port, 'is open')
         con.close()
      except:
         pass

   def threader():
      while True:
         worker = q.get()
         portscan(worker)
         q.task_done()
         
   q = Queue()
   startTime = time.time()
      
   for x in range(100):
      t = threading.Thread(target = threader)
      t.daemon = True
      t.start()
      
   for worker in range(1, 500):
      q.put(worker)
      
   q.join()
   print('Time taken:', time.time() - startTime)

main()