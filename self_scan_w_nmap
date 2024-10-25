#Imports nmap module
import nmap

nm = nmap.PortScanner()

#Assign target IP address or hostname
target = "scanme.nmap.org"

# Target for scan
nm.scan(target)

# Loops through scan results
for host in nm.all_hosts():
    #Displays host
    print("Host: ", host)
    #Displays state
    print("State: ", nm[host].state())
    for protos in nm[host].all_protocols():
        #Displays protocol being used
        print("Protocol: ", protos)
        ports = nm[host][protos].keys()
        for port in ports:
            #Prints host, state, protocol, and port information found open
            print("Port: ", port, "State: ", nm[host][protos][port]['state'])
    #Exports to file
    print(nm.csv())
