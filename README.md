# Assignment Task
Packet corruption.

I was tasked to create a C++ program to read a network capture packet, then locate all IP packets and corrupt the IP packet field such as:

1. TTL = 0
1. protocol = unknown
1. source add = destination add
1. source add = IP Multicast address
1. IP data length mismatch with UDP data length etc.

The input to the corruption should be user-specified.
Store the output into a file “xyz”

# Caveats
1. To create pcap, safest way to ensure compatibility with program is to ensure the link-type used to record the pcap file is using EN10MB. The C++ program is expecting header information of type EN10MB. While doing the assignment on my Macbook, using the default interface to be recorded for TCPDump packet recording outputs made TCPDump record using link-type PKTAP. Program cannot read the packet when link-type PKTAP (Apple DLT_PKTAP) is used. From my testing, running: ```sudo tcpdump -Xi en0 -c10 -w abc.pcap```
on my Macbook will ensure the pcap file created adheres the format the C++ is expecting.

1. Input pcap files to be read from the program is to be put inside directory ```./input/``` and named **abc.pcap**

1. protocol_file.txt needs to be present with their respective protocol numbers and name. protocol_file.txt must also be in directory ```./input/```

1. Output pcap files output to directory ```./output/``` and file is named xyz.pcap
