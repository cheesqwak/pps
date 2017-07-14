from scapy.all import *
import sys

my_filter = ""

#Dictionnaire de listes (clefs : IP, valeur : liste de ports)
ips_ports = dict()
udp_pkts = list()
udp_ctr = 0
TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
UDP_REVERSE = dict((UDP_SERVICES[k], k) for k in UDP_SERVICES.keys())

def host_port_digest(x):
    str_src_port = str(x.sport)
    str_dst_port = str(x.dport)

    #Verification que l'IP n'existe pas, auquel cas on la cree avec son premier tuple (port,ip) 
    if x.haslayer(TCP):
        if x['IP'].src not in ips_ports :
            ips_ports[x['IP'].src] = [(str_src_port,"tcp")]
        else :
        #Verification que le tuple (port,type) n'existe pas dans la case de clef "IP source"
            if str_src_port not in ips_ports[x['IP'].src][0] :
                ips_ports[x['IP'].src].append((str_src_port,"tcp"))

    if x.haslayer(UDP):
        if x['IP'].dst not in ips_ports :
            ips_ports[x['IP'].dst] = [(str_dst_port,"udp")]
        else:
            if str_dst_port not in ips_ports[x['IP'].dst][0]:
                ips_ports[x['IP'].dst].append((str_dst_port,"udp"))


def scan(x):
    global udp_pkts
    global udp_ctr

    if x.haslayer(IP) :
        if x.haslayer(TCP) :
            sys.stdout.write(". ")
            F = x.sprintf('%TCP.flags%')
            if F == 'SA':
                host_port_digest(x)

        if x.haslayer(UDP) : 
            sys.stdout.write("o ")
            #Elimination des reponses DNS sur l'hote local
            if not (x.haslayer(DNS) and x['UDP'].dport != 53 and x['UDP'].dport != 5353) :
                udp_ctr += 1
                udp_pkts.append(x)
        
        if x.haslayer(ICMP) :
            sys.stdout.write("<> ")
            if(x[1].code == 3) : #Check unreachable flag
                sys.stdout.write("x ")
                try :
                    if udp_ctr > 0 : 
                        if (x[4].chksum == udp_pkts[udp_ctr-1][2].chksum) : #Test if checksum are the same (icmp correspond to fail udp)
                            del(udp_pkts[udp_ctr-1])
                            udp_ctr -= 1
                except IndexError :
                    print("ICMP CHECKSUM OUT OF RANGE")
        sys.stdout.flush()


if __name__ == '__main__':
    #SNIFF
    print("Scanning...")
    sniff(prn=scan, filter=my_filter)
    
    #Parsing UDP packets
    for x in udp_pkts :
        host_port_digest(x)
    
    print(3*'\n')
    for ip in ips_ports : 
        print("-----------------------")
        print("Host "+ip+" : ")
        for port_type in ips_ports[ip] :
            int_port_type = int(port_type[0])
            if(port_type[1] == "tcp"):
                try :
                    service = TCP_REVERSE[int_port_type]
                except KeyError :
                    service = "<unknown>"
                print(port_type[0]+"/"+port_type[1]+"   open    "+service)
            if(port_type[1] == "udp"):
                try :
                    service = UDP_REVERSE[int_port_type]
                except KeyError :
                    service = "<unknown>"
                print(port_type[0]+"/"+port_type[1]+"   open    "+service)

        print("-----------------------\n")

