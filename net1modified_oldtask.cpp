#define NULL 0
#define TCPDUMP_MAGIC 0xa1b2c3d4	    /* Tcpdump Magic Number (Preamble)  */
#define PCAP_VERSION_MAJOR	2	    	/* Tcpdump Version Major (Preamble) */
#define PCAP_VERSION_MINOR	4	    	/* Tcpdump Version Minor (Preamble) */

#define DLT_NULL	0				    /* Data Link Type Null  */

#define DLT_EN10MB	1				    /* Data Link Type for Ethernet II 100 MB and above */
#define DLT_EN3MB	2			       	/* Data Link Type for 3 Mb Experimental Ethernet */

// Ethernet Header
#define ETHER_ADDR_LEN 6
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

struct ProtocolInfo {
    int number;
    string name;
};

typedef struct packet_header
{
	unsigned int magic;					/* Tcpdump Magic Number	*/
	unsigned short version_major;       /* Tcpdump Version Major */
	unsigned short version_minor;	    /* Tcpdump Version Minor */
	unsigned int thiszone;			    /* GMT to Local Correction */
	unsigned int sigfigs;			    /* Accuracy of timestamps */
	unsigned int snaplen;			    /* Max Length of Portion of Saved Packet */
	unsigned int linktype;			    /* Data Link Type */
} hdr;

typedef struct packet_timestamp
{
	unsigned int tv_sec;			    /* Timestamp in Seconds */
	unsigned int tv_usec;			    /* Timestamp in Micro Seconds */
	/* Total Length of Packet Portion (Ethernet Length until the End of Each Packet) */
	unsigned int caplen;
	unsigned int len;				    /* Length of the Packet (Off Wire) */
} tt;

typedef struct ether_header
{
	unsigned char edst[ETHER_ADDR_LEN]; 	/* Ethernet Destination Address */
	unsigned char esrc[ETHER_ADDR_LEN]; 	/* Ethernet Source Address */
	unsigned short etype;		            /* Ethernet Protocol Type */
} eth;

//GLOBAL VARIABLES
FILE *input;
FILE *output;
FILE *protocol;
vector<ProtocolInfo> protocolList;

//FUNCTIONS
void initializeProtocolList(const string& filename) {
    ifstream file(filename);
    string line;

    while (getline(file, line)) {
        istringstream iss(line);
        ProtocolInfo info;

        if (iss >> info.number >> info.name) {
            protocolList.push_back(info);
        }
    }
}

string protocolCheck(char a) {
    for (const auto& info : protocolList) {
        if (info.number == a) {
            return info.name;
        }
    }
    return "Unknown Protocol";
}

// Function to corrupt IP packets
void corruptIPPacket(unsigned char* packet,int userChoice) {
	if(((packet[0] >> 4) & 0xF) == 0x4){
		switch (userChoice){
		case 1:
    		// Set TTL to 0
    		packet[8] = 0;
			break;

		case 2:
    		// Set protocol to unknown (let's say 255)
    		packet[9] = 255;
			break;

		case 3:{
			int randomNumber = rand();
			int IPAddressByteSize=4;
			if (randomNumber%2==0){
    		memcpy(&packet[12], &packet[16], IPAddressByteSize);
			cout<<"Replacing src with destination"<<endl;
			}else{memcpy(&packet[16], &packet[12], IPAddressByteSize);
			cout<<"Replacing dest with src"<<endl;
			}
    		break;
			}
		case 4:
			// Set source address to IP Multicast address
    		packet[12] = 239;
    		packet[13] = 255;
    		packet[14] = 255;
    		packet[15] = 255;
			break;

		case 5:
    		// Set IP Total Length to mismatch with UDP Length (assuming UDP header size = 8)
			packet[2]=0;
			packet[3]=rand()%16;
    		break;

		default:
			break;
		}
	}
	else if(((packet[0] >> 4) & 0xF) == 0x6){
		switch (userChoice){
		case 1:
    		// Set Hop Limit to 0
    		packet[7] = 0;
			break;

		case 2:
    		// Set protocol to unknown
    		packet[6] = 255;
			break;

		case 3:{
			int randomNumber = rand();
			int IPAddressByteSize=16;
			if (randomNumber%2==0){
    		memcpy(&packet[8], &packet[24], IPAddressByteSize);
			cout<<"Replacing src with destination"<<endl;
			}else{memcpy(&packet[24], &packet[8], IPAddressByteSize);
			cout<<"Replacing dest with src"<<endl;
			}
    		break;
			}
		case 4:
			// Set source address to IP Multicast address
			packet[8] = 0xFF;
			for (int i = 9; i < 24; i++)
			{
				packet[i] = 0;
			}
			break;

		case 5:
			// Set IP Total Length to mismatch with UDP Length
			packet[5]=rand()%16;
			packet[6]=rand()%16;
    		break;

		default:
			break;
		}

	}
}

void promptUser(bool &corruptPcap,int &userChoice){
	char userInput;
	cout << "Would you like to corrupt the pcap? [Y/N]: ";
    cin >> userInput;
	try
	{
		if((corruptPcap = (userInput == 'y' || userInput == 'Y'))){
			do
			{	cout<<"What would you like to corrupt?"			          	  <<endl;
				cout<<"1. Packet's TTL"								   		  <<endl;
				cout<<"2. Packet's protocol"						          <<endl;
				cout<<"3. Source Address == Destination Address or vice versa"<<endl;
				cout<<"4. Set source address to IP multicast address"         <<endl;
				cout<<"5. Set IP data length to mismatch with UDP data length"<<endl;
				cin>>userChoice;
				if(!(userChoice<=5 && userChoice>0)){
				cout<<endl<<endl<<endl;
				cout<<"Invalid choice. Choices only range from 1 to 5."<<endl<<endl;
				cin.clear();
				cin.ignore();
				}
			}while (!(userChoice<=5 && userChoice>0));
		}	
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
	}
	
}

void printPacketInformation(unsigned char* currentPacket){
		printf("\n\n");
		printf("IP Protocol: IPv%x\n",((currentPacket[0] >> 4) & 0xF));
	if(((currentPacket[0] >> 4) & 0xF) == 0x4){
		printf("Source IP Address     : %d.%d.%d.%d\n",currentPacket[12],currentPacket[13],currentPacket[14],currentPacket[15]);
		printf("Destination IP Address: %d.%d.%d.%d\n",currentPacket[16],currentPacket[17],currentPacket[18],currentPacket[19]);
		printf("Protocol: %d (%s)",currentPacket[9],protocolCheck(currentPacket[9]).c_str());
	}else if(((currentPacket[0] >> 4) & 0xF) == 0x6){
		printf("Source IP Address     : %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		currentPacket[8],currentPacket[9],currentPacket[10],currentPacket[11],
		currentPacket[12],currentPacket[13],currentPacket[14],currentPacket[15],
		currentPacket[16],currentPacket[17],currentPacket[18],currentPacket[19],
		currentPacket[20],currentPacket[21],currentPacket[22],currentPacket[23]);
		printf("Destination IP Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
		currentPacket[24],currentPacket[25],currentPacket[26],currentPacket[27],
		currentPacket[28],currentPacket[29],currentPacket[30],currentPacket[31],
		currentPacket[32],currentPacket[33],currentPacket[34],currentPacket[35],
		currentPacket[36],currentPacket[37],currentPacket[38],currentPacket[39]);
		printf("Protocol: %d (%s)",currentPacket[6],protocolCheck(currentPacket[6]).c_str());	
	}
}

int main(int argc, char *argv[])
{
	unsigned int remain_len = 0;
	unsigned char temp=0, hlen, version, tlen;
	int i, count=0;
	struct packet_header hdr;			/* Initialize Packet Header Structure */
	struct packet_timestamp tt;			/* Initialize Timestamp Structure */
	struct ether_header eth;			/* Initialize Ethernet Structure */
    unsigned char buff;
	bool corruptPcap = false;
	int userChoice=NULL;
	//filepaths
	const string input_directory="./input/";
	const string output_directory="./output/";
	const string corrupted_pcap_filename="xyz.pcap";
	const string input_pcap_filename="abc.pcap";
	const string protocol_list_filename="protocol_file.txt";
	string corrupt_pcap_filepath=output_directory+corrupted_pcap_filename;
	string input_pcap_filepath=input_directory+input_pcap_filename;
	const string protocol_filepath=input_directory+protocol_list_filename;

	// Ask the user whether to corrupt the current packet
	promptUser(corruptPcap,userChoice);

// Initialize file pointers
	//output corrupted file
	output = fopen(corrupt_pcap_filepath.c_str(),"wb");
	if(!output){
		cout << "Cannot write to corrupted_output.pcap: "<<corrupt_pcap_filepath << endl;
		exit(EXIT_FAILURE);
	}

	//input of list of protocols
	try{
	initializeProtocolList(protocol_filepath);
	}catch(const std::exception& e){
		std::cerr << e.what() << '\n';
	}
	
	//input of pcap file to read from

	input = fopen(input_pcap_filepath.c_str(), "rb");
	if(!input){
		cerr << "Cannot open saved windump file: " << input_pcap_filepath<<endl;
		exit(EXIT_FAILURE);
	}else{
		fread((char *) &hdr, sizeof(hdr), 1, input);	/* Read & Display Packet Header Information */
		fwrite(&hdr, 1, sizeof(hdr), output);
		cout << "\n********** ********** PACKET HEADER ********** ***********" << endl;
		cout << "Preamble " << endl;
		cout << "Packet Header Length : " << sizeof(hdr) << endl;
		cout << "Magic Number : " << hdr.magic << endl;
		cout << "Version Major : " << hdr.version_major << endl;
		cout << "Version Minor : " << hdr.version_minor << endl;
		cout << "GMT to Local Correction : " << hdr.thiszone << endl;
		cout << "Jacked Packet with Length of : " << hdr.snaplen << endl;
		cout << "Accuracy to Timestamp   :  " << hdr.sigfigs  << endl;
		cout << "Data Link Type (Ethernet Type II = 1)  : " << hdr.linktype << endl;

		/* Use While Loop to Set the Packet Boundary */
		while(fread((char *) &tt, sizeof(tt), 1, input))  /* Read & Display Timestamp Information */
		{
			++count;

			if(count==0){
			fwrite((char *)&tt, sizeof(tt), 1, output);
			}

			cout << "********** ********** TIMESTAMP & ETHERNET FRAME ********** ***********" << endl;
			cout << "Packet Number: " << count << endl;  /* Display Packet Number */
			cout << "The Packets are Captured in : " << tt.tv_sec << " Seconds" << endl;

			cout << "The Packets are Captured in : " << tt.tv_usec << " Micro-seconds" << endl;
			/* Use caplen to Find the Remaining Data Segment */
			cout << "The Actual Packet Length: " << tt.caplen << " bytes" << endl;  
			cout << "Packet Length (Off Wire): " << tt.len << " bytes" << endl;
						
			fread((char *) &eth, sizeof(eth), 1, input); /* Read & display ethernet header information */
			cout << "Ethernet Header Length  : " << sizeof(eth) <<" bytes" << endl;

			fwrite((char *)&tt.tv_sec, sizeof(tt.tv_sec), 1, output);
			fwrite((char *)&tt.tv_usec, sizeof(tt.tv_usec), 1, output);
			fwrite((char *)&tt.caplen, sizeof(tt.caplen), 1, output);
			fwrite((char *)&tt.len, sizeof(tt.len), 1, output);
			fwrite((char *)&eth, sizeof(eth), 1, output);
			
			//1171103354 PAUL JOHN C ESCOBIA
			//PACKET CONTENT, EDIT STARTS HERE
			//
			printf("\nNo corruption:\n");
			unsigned char* currentPacket = new unsigned char[tt.caplen-14];
			
			for (i=0;i<tt.caplen -14;i++){ 
				fread((char *) &buff, sizeof(buff), 1 , input);
				currentPacket[i] = buff;
                printf("%02x ", currentPacket[i]);
					if((i+1)%16==0){
						cout<<endl;
					}
             }
			printPacketInformation(currentPacket);
	
			//CORRUPT PACKETS
			if (corruptPcap) {
			cout<<endl<<endl;
			cout<<"After Corruption: "<<endl;
            corruptIPPacket(currentPacket,userChoice);
				for (i=0;i<tt.caplen -14;i++){ 
            	    printf("%02x ", currentPacket[i]);
					if(i!=0 && i%16==0){
						cout<<endl;
					}
            	}
				fwrite(currentPacket, 1, tt.caplen - 14, output);
				printPacketInformation(currentPacket);
        	}

			printf("\n\n");
			delete[] currentPacket;
			//END OF EDIT FOR ASSIGNMENT
			//1171103354
			//PAUL JOHN C ESCOBIA
          
		} // end while 
	} // end main else 


	fclose(input); // Close input file
	fclose(output);// Close output file
		
	return (0);
}