#ifndef ARP_H
#define ARP_H

#define MACSIZE 6
#define IPSIZE 4

#define PACKET_FORWARD_TIMEOUT 50
#define ARP_SPOOF_TIMEOUT 1000

#include "systemInterface.h"
#include <pcap.h>
#include <wx/thread.h>

//Little-endian
#define ARP_REPLY 0x0200
#define ARP_REQUEST 0x100

#ifdef WIN32
__declspec( align( 1 ) ) //MSVC
#endif
struct Ethernet {
	u_char etherDestMac[MACSIZE];
	u_char etherSrcMac[MACSIZE];
	u_short etherProtoType;
}
#ifndef WIN32
__attribute__ ((packed)) //GCC
#endif
;

#ifdef WIN32
__declspec( align( 1 ) ) //MSVC
#endif
struct ARP {
	u_short arpHardType; //Type of hardware address
	u_short arpProtoType; //Type of address to map to
	u_char arpHardSize; //Size (in bytes) of hardware address
	u_char arpProtoSize; //Size (in bytes) of address to map to
	u_short arpOpType; //ARP Operation Type (Request/Response) or RARP types
	u_char arpSenderMAC[MACSIZE]; //MAC address of packet originator
	u_char arpSenderIP[4]; //IP address of packet originator
	u_char arpDestMAC[MACSIZE]; //MAC address of the target host (or broadcast)
	u_char arpDestIP[4]; //IP address of target host
}
#ifndef WIN32
__attribute__ ((packed)) //GCC
#endif
;

#ifdef WIN32
__declspec( align( 1 ) ) //MSVC
#endif
struct ARPDataFrame {
	Ethernet ethData;
	ARP arpData;
}
#ifndef WIN32
__attribute__ ((packed)) //GCC
#endif
;

// class to send arp packets. Constructs the packet in constructor, and just sends
class ArpThread : public wxThread {
public:
	//sends an ARP to the target, telling it the gateway is at macSrc (or if null, the real gateway source mac)
	static void sendTargetedArp(wxString ipstr, pcap_if_t* interf, wxTextCtrl* output, const char* macSrc = NULL);
	//starts an
	static ArpThread * startAprThread(wxString ipstr, pcap_if_t* interf, wxTextCtrl* output, bool * send, bool forward = true);

	wxThreadError Create(bool * send_, pcap_if_t* interf_, const u_char ethSrcMac[], const u_char ethDstMac[], const u_char srcIP[], const u_char dstIP[], bool forward = true) {
		if (sizeof(ARPDataFrame) != 42)
			return wxTHREAD_MISC_ERROR; // arp struct messed up (most likely alignment)
		send = send_;
		interf = interf_;
		forwarding = forward;
		// construct packet
		//Ethernet Header
		memcpy(frame.ethData.etherDestMac, ethDstMac, MACSIZE);
		memcpy(frame.ethData.etherSrcMac, ethSrcMac, MACSIZE);
		frame.ethData.etherProtoType = 0x0608; //ARP

		//ARP Packet
		frame.arpData.arpHardType = 0x0100;
		frame.arpData.arpHardSize = MACSIZE;
		frame.arpData.arpProtoSize = 4;
		frame.arpData.arpProtoType = 0x0008; //IP

		frame.arpData.arpOpType = ARP_REPLY; // ARP_REQUEST? That works better on linux. reply on windows. See Defcon 15 presentation "ARP reloaded"
		memcpy(frame.arpData.arpSenderMAC, ethSrcMac, MACSIZE);
		memcpy(frame.arpData.arpSenderIP, srcIP, IPSIZE);
		memcpy(frame.arpData.arpDestMAC, ethDstMac, MACSIZE);
		memcpy(frame.arpData.arpDestIP, dstIP, IPSIZE);

		return wxThread::Create();
	};
	bool sendArp(pcap_t *device) {
		return pcap_sendpacket(device,(const u_char*)&frame,sizeof(frame))==0;
	}
private:
	virtual void* Entry();
	void forward(pcap_t* interf, const u_char* pkt_data, int packetlen); //forward packet to gateway

	bool forwarding;
	u_char localMac[6];
	u_char routerMac[6];
	ARPDataFrame frame;
	bool * send;
	pcap_if_t* interf;
};

#endif
