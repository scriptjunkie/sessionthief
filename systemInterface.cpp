
#include "systemInterface.h"
#include <wx/dir.h>
#include <wx/textfile.h>
#include <wx/process.h>
#include <wx/string.h>

// gets gateway from adapters info or parsing route on linux
wxString SystemInterface::getGateway(pcap_if_t* interf) {
    wxString result = _T("");
    wxString interfname = wxString::FromAscii(interf->name);
#ifdef WIN32    //WINDOWS
    PIP_ADAPTER_INFO pAdapterInfo; //modified/copied from msdn. Blame them.
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) 
        return _T("");
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
        if (pAdapterInfo == NULL)
            return _T("");
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		for(pAdapter = pAdapterInfo;pAdapter;pAdapter = pAdapter->Next){
			if(interfname.Contains(wxString::FromAscii(pAdapter->AdapterName))){
				result = wxString::FromAscii(pAdapter->GatewayList.IpAddress.String);
				break;
			}
		}
    } else {
        return _T("");
    }
    if (pAdapterInfo)
        free(pAdapterInfo);

#else        // LINUX - needs root privileges
    //ok maybe not the best way to do this, but sure seems easiest
    wxProcess* proc = wxProcess::Open(_T("route -n"));
    if(proc == NULL){
        return result;
    }
    wxInputStream* is = proc->GetInputStream();
    wxString s = _T("");
    char buf[128];
    while(!is->Eof()){
        is->Read(buf,128);
        s.append(wxString::FromUTF8(buf,is->LastRead()));
    }

    // parse through it. until we find gateway line
    unsigned int pos = 0;
    wxString line = s.Mid(pos);
    while(!line.StartsWith(_T("0.0.0.0")) && pos < s.Len()){
        pos = s.find(_T("\n"),pos+1);
        line = s.Mid(pos+1);
    }
    if(pos == s.npos)
        return line;
    int index = 0;    // move index to first char from 1-9
    while (line.at(index) <= '0' || line.at(index) > '9')
        index++;
    // continue until ip address is found
    for (int endindex = index; line.at(endindex) == '.' || (line.at(endindex) >= '0' && line.at(endindex) <= '9'); endindex++)
        result.append(1, line.at(endindex));

#endif
    return result;
}

//Finds the local ip and copies to output
wxString SystemInterface::getLocalIp(const pcap_if_t* interf, unsigned char* output) {
    wxString ipthing = _T("");
#ifdef WIN32 //local ip seems to actually work on winpcap
    ipthing.append(wxString::FromAscii(inet_ntoa(((struct sockaddr_in *) (interf->addresses->addr))->sin_addr)));
    if (output)
        memcpy(output, &(((struct sockaddr_in *) (interf->addresses->addr))->sin_addr), sizeof (((struct sockaddr_in *) (interf->addresses->addr))->sin_addr));
#else
    struct ifreq ifr; //libpcap on linux apparently can't find the ip address. Morons.
    struct sockaddr_in saddr;
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    strcpy(ifr.ifr_name, interf->name);
    ioctl(fd, SIOCGIFADDR, &ifr);
    saddr = *((struct sockaddr_in *) (&(ifr.ifr_addr))); // is the address
    ipthing.append(wxString::FromAscii(inet_ntoa(saddr.sin_addr)));
    if (output)
        memcpy(output, &(saddr.sin_addr), sizeof (saddr.sin_addr));
#endif
    return ipthing;
}

// gets mac from adapter info
// uses interfInt to get the correct interface, destMac required
wxString SystemInterface::getLocalMac(u_char* destMac) {
    if (destMac == NULL)
        return wxString(_T(""));
#ifdef WIN32    // WINDOWS  wow is this ugly. Either way.
    IP_ADAPTER_INFO AdapterInfo[16];       // Allocate information
                                         // for up to 16 NICs
    DWORD dwBufLen = sizeof(AdapterInfo);  // Save memory size of buffer
    DWORD dwStatus = GetAdaptersInfo( AdapterInfo, &dwBufLen);
    if(dwStatus != ERROR_SUCCESS)
        return wxString(_T(""));
    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo; // Contains pointer to
                                                // current adapter info
    // go to selected interf
	pcap_if_t* alldevs = firstdev;
	for(int i = 0; i < interfInt; i++)
        alldevs = alldevs->next;
	while(pAdapterInfo != NULL){
		wxString adapterName(pAdapterInfo->AdapterName);
		wxString pcapName(alldevs->name);
		if (pcapName.Contains(adapterName))
			break;
        pAdapterInfo = pAdapterInfo->Next;
	}
    //copy mac address
    memcpy(destMac,pAdapterInfo->Address,sizeof(pAdapterInfo->Address));
    //turn it into a string
    char NetName[20];
    sprintf( NetName,"%02x:%02x:%02x:%02x:%02x:%02x",
                 destMac[0], destMac[1], destMac[2], destMac[3], destMac[4], destMac[5]);
    return wxString::FromAscii(NetName);
#else        // LINUX

    //get name
    pcap_if_t *dev = firstdev;
    for(int i = 0; i < interfInt; i++)
        dev = dev->next;

    int fd;
    struct ifreq ifr;
    char namebuffer[100];    //get buffer ready for the name
    memset(namebuffer,0,100);
    fd = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL)); // open socket
    strcpy(ifr.ifr_name, dev->name); // get device name
    ioctl(fd, SIOCGIFHWADDR, &ifr); // retrieve MAC address

    unsigned char * hwaddr = (unsigned char*)&ifr.ifr_hwaddr.sa_data;
    sprintf(namebuffer,"%2x:%2x:%2x:%2x:%2x:%2x",(int)hwaddr[0],(int)hwaddr[1],(int)hwaddr[2],(int)hwaddr[3],(int)hwaddr[4],(int)hwaddr[5]);
    close(fd);

    // output binary
    memcpy(destMac,hwaddr,MACSIZE);
    wxString result = wxString::FromAscii(namebuffer);
    return result;
#endif
}

//check if browser is running
bool SystemInterface::isProcessRunning(const wxChar* processName){
#ifdef WIN32
    //from win api example from msdn. Blame them.
    TCHAR szProcessName[MAX_PATH] = TEXT("");
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;
    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
        throw _T("Error - process list cannot be opened");
    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);
    // for each process.
    for ( i = 0; i < cProcesses; i++ ){
        if( aProcesses[i] == 0 )
            continue;
        //open
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ, FALSE, aProcesses[i] );
        if (hProcess == NULL)
            continue;
        HMODULE hMod;
        DWORD cbNeeded;
        // Get the process name
        if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
            GetModuleBaseName( hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR) );
#ifndef UNICODE
        wxString name = wxString::FromAscii(szProcessName);
#else 
		wxString name(szProcessName);
#endif
        CloseHandle( hProcess );
        if(name.Contains(processName))
            return true;
    }
#else
    //Linux; search proc directory for firefox
    wxDir directory(_T("/proc"));
    if (!directory.IsOpened())
        throw _T("Error - /proc cannot be opened");

    wxString subfolderName;
    directory.GetFirst(&subfolderName,wxEmptyString,wxDIR_DIRS);
    while(directory.GetNext(&subfolderName)){
        if(!wxFile::Exists(_T("/proc/")+subfolderName+_T("/cmdline")))
            continue;
        wxTextFile tf;
        tf.Open(_T("/proc/")+subfolderName+_T("/cmdline"));
        if(tf.GetFirstLine().EndsWith(processName)){
            tf.Close();
            return true;
        }
        tf.Close();
    }
#endif
    return false;
}

//simple version of getTargetMac
wxString SystemInterface::getTargetMac(const u_char dstIP[], const pcap_if_t* interf, u_char* destMac) {
    u_char localIp[4];
    getLocalIp(interf, localIp);
    u_char localMac[MACSIZE];
    getLocalMac(localMac);
    return getTargetMac(localMac, localIp, dstIP, interf, destMac);
}

//look up mac using pcap and ARP (sends a request and listens for a response)
//ethSrcMac, srcIP, dstIP, interf in
//destMac out (Required)
wxString SystemInterface::getTargetMac(const u_char ethSrcMac[], const u_char srcIP[], const u_char dstIP[], const pcap_if_t* interf, u_char* destMac) {
    //get interface
    pcap_t *adhandle;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    //full scan every
    int timeout = 100;
    // if interface exists, and we can open...
    if ((adhandle = pcap_open_live(interf->name, 65536, 0, timeout, NULL)) == NULL)
        return (_T(""));

    // get filter for arp. we can assume all packets we receive are arp packets
    struct bpf_program fp; // holds compiled filter
    if (pcap_compile(adhandle, &fp, "arp", 0, 0) == -1 || pcap_setfilter(adhandle, &fp) == -1)
        return (_T(""));

    //Set up request
    ARPDataFrame frame;
    //Ethernet packet
    memset(frame.ethData.etherDestMac, 0xFF, MACSIZE);
    memcpy(frame.ethData.etherSrcMac, ethSrcMac, MACSIZE);
    frame.ethData.etherProtoType = 0x0608; //ARP
    //ARP Packet
    frame.arpData.arpHardType = 0x0100;
    frame.arpData.arpHardSize = MACSIZE;
    frame.arpData.arpProtoSize = 4;
    frame.arpData.arpProtoType = 0x0008; //IP
    frame.arpData.arpOpType = ARP_REQUEST;
    memcpy(frame.arpData.arpSenderMAC, ethSrcMac, MACSIZE);
    memcpy(frame.arpData.arpSenderIP, srcIP, IPSIZE);
    memset(frame.arpData.arpDestMAC, 0xFF, MACSIZE);
    memcpy(frame.arpData.arpDestIP, dstIP, IPSIZE);
    //Set IP
    *((unsigned int*) (&(frame.arpData.arpDestIP[0]))) = *((unsigned int*) (&(dstIP[0])));
    //send request
    pcap_sendpacket(adhandle, (const u_char*) & frame, sizeof (frame));

    // Until your timeout, (one second or something) or 15 arps
    // (linux clock() always returns same value for me) wait for response
    clock_t start = clock();
    int packs = 0;
    while (clock() - start < CLOCKS_PER_SEC*10 && packs < 15) {
        packs++;
        if (pcap_next_ex(adhandle, &header, &pkt_data) != 1) 
            continue;
        ARPDataFrame* frame2 = (ARPDataFrame*) pkt_data;
        //get source IP
        unsigned int sIp = *((unsigned int*) (frame2->arpData.arpSenderIP));
        //ignore if this is not a reply or not from who we pinged
        if ( frame2->arpData.arpOpType != ARP_REPLY ||
                *((unsigned int*) (frame2->arpData.arpDestIP)) != *((unsigned int*) (frame.arpData.arpSenderIP)) ||
                sIp != *((unsigned int*) (frame.arpData.arpDestIP))
                ) 
            continue;

        //get mac and turn it into a string
    memcpy(destMac, frame2->arpData.arpSenderMAC, MACSIZE);
        char NetName[20];
        sprintf(NetName, "%02x:%02x:%02x:%02x:%02x:%02x",
                destMac[0], destMac[1], destMac[2], destMac[3], destMac[4], destMac[5]);
        return wxString::FromAscii(NetName);
    }//end while(timer)
    throw _T("No arp reply received!"); //fail! No reply received.
}

// print ips from first 50 packets
void SystemInterface::printIps(wxTextCtrl* textBox, pcap_if_t* interf) {
    set<unsigned int> ips;
    pcap_t *adhandle;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    // Open the device
    if ((adhandle = pcap_open_live(interf->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL)) == NULL) {
        * textBox << _T("Unable to open the adapter. ") << wxString::FromAscii(interf->name) << _T("\n");
        return;
    }
    //Only accept IP packets
    struct bpf_program fp;
    if (pcap_compile(adhandle, &fp, "ip", 0, 0) == -1 ||  pcap_setfilter(adhandle, &fp) == -1)
        return;
    u_int ipHeaderOffset = SystemInterface::getIpOffset(adhandle);

    // Start getting 50 packets
    for (int i = 0; i < 50; i++) {
        if (pcap_next_ex(adhandle, &header, &pkt_data) == 1) {
            ips.insert(*((unsigned int*) (&(pkt_data[ipHeaderOffset+12])))); // get ips
            ips.insert(*((unsigned int*) (&(pkt_data[ipHeaderOffset+16]))));
        } else {
            wxString num; //show progress. (on MSW; anyway. On GTK it shows up after it runs.)
            num << ips.size();
            * textBox << num << _T(" ips...\n"); // oh well.
        }
    }

    * textBox << _T("\n");
    //Print ip addresses
    for (set<unsigned int>::iterator it = ips.begin(); it != ips.end(); it++)
        * textBox << ipToString(*it) << _T("\n");
    pcap_close(adhandle);
}

// asks user to select a device, and print it with mac
pcap_if_t* SystemInterface::getInterface() {
    // Retrieve the device list
    if (pcap_findalldevs(&firstdev, NULL) == -1 || firstdev == NULL) {
        wxMessageDialog dialogErr(NULL, _T("ERROR NO DEVICES"), _T("No interfaces!"));
        dialogErr.ShowModal();
        exit(1);
    }

    // GETTING LIST
    vector<pcap_if_t *> devs;
    pcap_if_t * alldevs = firstdev; // walk linked list with alldevs
    while (alldevs != NULL) {
        devs.push_back(alldevs);
        alldevs = alldevs->next;
    }
    wxString* choices = new wxString[devs.size()];
    for (u_int i = 0; i < devs.size(); i++) {
        wxString tempStr(_T(""));
        if (devs.at(i)->description != NULL)
            tempStr.append(wxString::FromAscii(devs.at(i)->description)+_T("; "));
        if (devs.at(i)->name != NULL)
            tempStr.append(wxString::FromAscii(devs.at(i)->name));
        choices[i] = tempStr;
    }
    //Ask user which one
    wxSingleChoiceDialog dialog(NULL, _T("Available interfaces:"), _T("Please select one:"), devs.size(),
            choices, NULL, wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxOK | wxCANCEL | wxCENTRE | wxSTAY_ON_TOP);
    if (dialog.ShowModal() == wxID_OK) {
        interfInt = dialog.GetSelection();
        alldevs = devs.at(interfInt);
    } else { //looks like the user didn't want to do anything
        wxMessageDialog dialog(NULL, _T("No interface selected"), _T("No interface!"),wxOK | wxSTAY_ON_TOP);
        dialog.ShowModal();
        exit(1);
    }

    delete [] choices;
    return alldevs; // Returns the first (so it can be freed later)
}

//find offset for ip header (link layer header length)
u_int SystemInterface::getIpOffset(pcap_t* interf) {
    //Get datalink type and corresponding header lengths
    //see http://www.manpagez.com/man/7/pcap-linktype/
    int type = pcap_datalink(interf);
    if (type == DLT_EN10MB)
        return 14;
    else if (type == DLT_RAW)
        return 0;
    else if (type == DLT_LOOP)
        return 4;
    else if (type == DLT_LINUX_SLL)
        return 16;
    else
        throw _T("Error: unknown link type");
}

//static vars
pcap_if_t* SystemInterface::firstdev; // global device list head. Interfaces are global.
int SystemInterface::interfInt; // global device int
wxString SystemInterface::portFilter; // global port filter
