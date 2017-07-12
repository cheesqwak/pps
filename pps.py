from scapy.all import *

#Dictionnaire de listes (clefs : IP, valeur : liste de ports)
ips_ports = dict()

def get_ports(x):
    global liste_ports

    #TCP
    if x.haslayer(TCP) and x.haslayer(IP) :
        F = x.sprintf('%TCP.flags%')
        if F == 'SA':
            if x['IP'].src not in ips_ports :
                str_port = str(x.sport)
                print("New host added : "+x['IP'].src+", port : "+str_port)
                ips_ports[x['IP'].src] = [str_port]   
            else : 
                str_port = str(x.sport)
                if str_port not in ips_ports[x['IP'].src] :
                    print("New port added for host "+x['IP'].src+" : "+str_port)
                    ips_ports[x['IP'].src].append(str_port)

#SNIFF
rep = sniff(prn=get_ports)

print("----------------------")
print("RESULTS : \n")
for ip in ips_ports : 
    print("Host "+ip+" : ")
    for port in ips_ports[ip] :
        print(port+"/tcp    open")
    print("----------------------")

