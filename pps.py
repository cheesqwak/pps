from scapy.all import *
from threading import Thread
#import sys
import time
import signal
import curses

FILTER = ""

#Dictionnaire de listes (clefs : IP, valeur : liste de ports)
ips_ports = dict()
udp_pkts = list()
pkt_ctr = 0
udp_ctr = 0
TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
UDP_REVERSE = dict((UDP_SERVICES[k], k) for k in UDP_SERVICES.keys())

def host_port_digest(x):
    tcp_struct = [str(x.sport), "tcp"]
    udp_struct = [str(x.dport), "udp"]
    transports = [tcp_struct, udp_struct]
    ips = [x['IP'].src, x['IP'].dst]

    #Verification que l'IP n'existe pas, auquel cas on la cree avec son premier tuple (port,type) 
    tcp_udp_bool = 1;
    if x.haslayer(TCP):
        tcp_udp_bool = 0
    if ips[tcp_udp_bool] not in ips_ports :
        ips_ports[ips[tcp_udp_bool]] = [(transports[tcp_udp_bool][0],transports[tcp_udp_bool][1])]
    else :
    #Verification que le tuple (port,type) n'existe pas dans la case de clef "IP source"
        a = False
        for ip_port in ips_ports[ips[tcp_udp_bool]] :
            if transports[tcp_udp_bool][0] == ip_port[0] :
                a = True
        if not a :
            ips_ports[ips[tcp_udp_bool]].append((transports[tcp_udp_bool][0],transports[tcp_udp_bool][1]))


def construct_display():
    global ips_ports
    if(bool(ips_ports)):
        res = ('RESULTS\n')
        for ip in ips_ports : 
            res += ("-----------------------\n")
            res += ("Host "+ip+" : \n")
            for port_type in ips_ports[ip] :
                int_port_type = int(port_type[0])
                if(port_type[1] == "tcp"):
                    try :
                        service = TCP_REVERSE[int_port_type]
                    except KeyError :
                        service = "<unknown>"
                    res += (port_type[0]+"/"+port_type[1]+"   open    "+service+"\n")
                if(port_type[1] == "udp"):
                    try :
                        service = UDP_REVERSE[int_port_type]
                    except KeyError :
                        service = "<unknown>"
                    res += (port_type[0]+"/"+port_type[1]+"   open    "+service+"\n")
            res += ("-----------------------\n\n")
        return res


def scan(x):
    global udp_pkts
    global pkt_ctr
    global udp_ctr

    if x.haslayer(IP) :
        pkt_ctr += 1
        if x.haslayer(TCP) :
            #sys.stdout.write(". ")
            F = x.sprintf('%TCP.flags%')
            if F == 'SA':
                host_port_digest(x)

        if x.haslayer(UDP) : 
            #sys.stdout.write("o ")
            #Elimination des reponses DNS sur l'hote local
            if not (x.haslayer(DNS) and x['UDP'].dport != 53 and x['UDP'].dport != 5353) :
                udp_ctr += 1
                udp_pkts.append(x)
        
        if x.haslayer(ICMP) :
            #sys.stdout.write("<> ")
            if(x[1].code == 3) : #Check unreachable flag
                #sys.stdout.write("x ")
                try :
                    if udp_ctr > 0 : 
                        if (x[4].chksum == udp_pkts[udp_ctr-1][2].chksum) : #Test si les checksums sont egaux (cas du fail UDP)
                            del(udp_pkts[udp_ctr-1])
                            udp_ctr -= 1
                except IndexError :
                    pass
        #Refresh des trames UDP
        if (pkt_ctr % 3) == 0:
            for x in udp_pkts :
                host_port_digest(x)

        #Refresh d'affichage

        #res = construct_display()
        #if res :
        #    sys.stdout.write("\r"+res)
        #    sys.stdout.flush()
        #    #if test_res != res: 
        #        #    test_res = res
        
        
def display_scan(window):
    #while True:
    res = construct_display()
    if res :
        window.addstr(1, 1, res)
        window.refresh()
        time.sleep(0.5)
    else :
        time.sleep(0.5)

        #test_res = ""
        #if res : 
        #    if test_res != res :
        #        test_res = res
        #        window.addstr(1, 1, test_res)
        #        window.refresh()
        #        time.sleep(0.1)

THREADS = []

def handler(signal, frame):
    global THREADS
    print "Ctrl-C.... Exiting"
    for t in THREADS:
        t.alive = False
    sys.exit(0)

class Displayer(Thread):
    def __init__(self):
        self.alive = True
        Thread.__init__(self)

    def run(self):
        while self.alive:
            try :
                curses.wrapper(display_scan)
            except : 
                pass

class Sniffer(Thread):
    def __init__(self):
        self.alive = True
        Thread.__init__(self)

    def run(self):
        sniff(prn=scan, filter=FILTER)   

def main():
    global THREADS
    thread_display = Displayer()
    thread_sniffer = Sniffer()
    THREADS.append(thread_display)
    THREADS.append(thread_sniffer)
    thread_display.deamon = True
    thread_display.start()
    thread_sniffer.deamon = True
    thread_sniffer.start()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handler)
    main()
    while True:           
        time.sleep(1)
        signal.pause()    
