#ifndef SYSTEMINTERFACE_H
#define SYSTEMINTERFACE_H

//global functions to get local system information, do network-related tasks.
//Mostly platform-specific abstractions

//tcp defines
#define ACK_FLAG (int)0x10
#define PSH_FLAG (int)0x08
#define RST_FLAG (int)0x04
#define SYN_FLAG (int)0x02
#define FIN_FLAG (int)0x01

#define HAVE_REMOTE

//std template library containers
#include <set>
#include <vector>
using namespace std;

// platform specific network includes
#ifdef WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <psapi.h>
//for netbios stuff
typedef struct _ASTAT_ {
    ADAPTER_STATUS adapt;
    NAME_BUFFER    NameBuff [30];
}ASTAT, * PASTAT;
#else
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#endif

//wxWidgets includes
#include <wx/string.h>
#include <wx/textctrl.h>
#include <wx/choicdlg.h>
#include <wx/msgdlg.h>
#include <wx/process.h>
#include <wx/stream.h>

//pcap
#include <pcap.h>
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

//project includes
#include "arp.h"

//abstracts local computer calls, etc.
class SystemInterface{
public:
    //platform-specific in_addr manipulation
    static unsigned long in_addrTos_addr(in_addr addr){
#ifdef WIN32
        return (unsigned long) addr.S_un.S_addr;
#else
        return (unsigned long) addr.s_addr;
#endif
    }
private:
    //simple helper function to return # of 1's in a long
    static int onesCount(unsigned long number) {
        int result = 0;
        unsigned long a = 1;
        for (u_int i = 0; i < sizeof (unsigned long) *8; i++) {
            if (number & a)
                result++;
            a *= 2;
        }
        return result;
    }
public:
    //information about local computer
    static wxString getGateway(pcap_if_t* interf);
    static wxString getLocalIp(const pcap_if_t* interf, unsigned char* output = NULL);
    static wxString getLocalMac(u_char* destMac= NULL);
    static pcap_if_t* getInterface();
    static int getNetmaskBits(pcap_if_t* interf){
        if (interf->addresses != NULL && interf->addresses->netmask != NULL) {
            in_addr netmask = ((struct sockaddr_in *) interf->addresses->netmask)->sin_addr;
            return onesCount(in_addrTos_addr(netmask));
        } else {
            return 24; // assume class C subnet if pcap can't figure it out
        }
    }
    static u_int getIpOffset(pcap_t* interf);
    static bool isEthernet(pcap_if_t* interf){
        pcap_t *adhandle = pcap_open_live(interf->name, 65536,  0, 1000, NULL );
        bool isEth = pcap_datalink(adhandle) == DLT_EN10MB;
        pcap_close(adhandle);
        return isEth;
    }

    //look up mac of a computer
    static wxString getTargetMac(const u_char dstIP[], const pcap_if_t* interf, u_char* destMac);
    static wxString getTargetMac(const u_char ethSrcMac[], const u_char srcIP[], const u_char dstIP[], const pcap_if_t* interf, u_char* destMac);
    
    //check if browser is running already
    static bool isProcessRunning(const wxChar* processName);

    //collect IPs heard on air
    static void printIps(wxTextCtrl* textBox, pcap_if_t* interf);

    // pretty much inet_ntoa for unsigned ints and wxStrings
    static wxString ipToString(unsigned int ipbinary) {
        in_addr ip; //Put IP in box
#ifdef WIN32
        ip.S_un.S_addr = ipbinary;
#else
        ip.s_addr = ipbinary;
#endif
        return wxString::FromAscii(inet_ntoa(ip));
    }

    //static vars
    static pcap_if_t* firstdev; // global device list head. Interfaces are global.
    static int interfInt; // global device int
    static wxString portFilter; // global port filter
};

#endif
