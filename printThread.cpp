#include "nviewFrame.h"
#include "printThread.h"
DEFINE_EVENT_TYPE(mwEVT_THREAD)

//checks a new tcp packet against the existing set of unfinished tcp gets
//we check the connection (ip and port) but NOT sequence numbers, since it is possible
//for us to receive the start and miss a few headers but still get the cookie
bool PrintThread::checkComplete(wxString& dataStr, const u_char * pkt_data, int size, int tcpHeaderOffset) {
    //data offset (read the rfc)
    int offset = tcpHeaderOffset + 4 * ((pkt_data[tcpHeaderOffset + 12] & 0xF0) >> 4);
    // if this has no data, ignore (we should be guaranteed tcp packet)
    if (size <= offset)
        return false;
    //get connection info
    u_int srcIp = *((u_int*) (&(pkt_data[tcpHeaderOffset-8])));
    u_int dstIp = *((u_int*) (&(pkt_data[tcpHeaderOffset-4])));
    u_short srcPort = (pkt_data[tcpHeaderOffset] << 8) + pkt_data[tcpHeaderOffset+1];
    u_short dstPort = (pkt_data[tcpHeaderOffset+2] << 8) + pkt_data[tcpHeaderOffset+3];

    vector<ConnectionInfo>::iterator indx = partialGets.begin();
    // see if this is a completion to a previously started get; if so append data
    bool found = false;
    while (indx != partialGets.end()) {
        //if it matches it is our connection, so append data
        if (indx->srcIp == srcIp && indx->dstIp == dstIp && indx->srcPort == srcPort && indx->dstPort == dstPort) {
            indx->buffer.append(dataStr);
            dataStr = indx->buffer;
            found = true;
            break;
        }
        indx++;
    }
    //is this new? 
    bool isGet = dataStr.StartsWith(_T("GET"));
    //is it complete? (The \r\n\r\n check is more reliable than PSH flag)
    bool end = dataStr.EndsWith(_T("\r\n\r\n"));
    // if new partial GET, add to vector
    if (!found && !end && isGet) { 
        ConnectionInfo inf (srcIp,dstIp,srcPort,dstPort,dataStr);
        partialGets.push_back(inf);
        
    } else if (found && end) {// if it is complete and in list, remove from list.
        partialGets.erase(indx);
    }
    return end && (found || isGet); //return true if complete get or completion of a previous get.
}

// prints tcp traffic
wxThread::ExitCode PrintThread::Entry() {
    pcap_t *adhandle;
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    unsigned int sourceIp = 0;

    //get interface
    if ((adhandle = pcap_open_live(interf->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL)) == NULL)
        return  (wxThread::ExitCode)-1;
    int tcpHeaderOffset = 20 + SystemInterface::getIpOffset(adhandle);

    // get filter for tcp. Not using filter to get ip addresses.
    struct bpf_program fp;
    //on some versions of pcap, pcap_compile takes a char* and not a const char*. Cast.
    if (pcap_compile(adhandle, &fp, const_cast <char*>((const char*)(SystemInterface::portFilter.ToAscii())), 0, 0) == -1 ||
            pcap_setfilter(adhandle, &fp) == -1)
        return  (wxThread::ExitCode)-1;

    // loop for each packet, while keepCapturing is true
    while (*keepCapturing) {
        if (pcap_next_ex(adhandle, &header, &pkt_data) != 1) 
            continue;
        //ignore if we have a target and packet is not from target
        sourceIp = *((int*) (&(pkt_data[tcpHeaderOffset - 8])));
        if (targetIp != (u_int)-1 && targetIp != sourceIp) 
            continue;
        //get data; offset from start of packet is tcpHeaderOffset + tcp offset
        int offset = tcpHeaderOffset + 4 * ((pkt_data[tcpHeaderOffset + 12] & 0xF0) >> 4);
        wxString dataStr = wxString::FromUTF8((const char*) (pkt_data + offset),header->caplen - offset);
        // send if it is a complete get, or a completion of a previous get
        if (dataStr.length() > 0 && checkComplete(dataStr, pkt_data, header->caplen, tcpHeaderOffset))
            sendMessage(dataStr, sourceIp);
    }
    pcap_close(adhandle); // we're done, clean up.
    return 0;
}// end Entry()  [prints tcp traffic]

// send http get and source ip to parent
void PrintThread::sendMessage(wxString & msg, u_int sourceIp) {
    wxCommandEvent evt(mwEVT_THREAD, wxID_ANY);
    try {
        //send new Request
        evt.SetClientData(new Request(msg, sourceIp));
        mainFrame->AddPendingEvent(evt);
    }catch(const wxChar * WXUNUSED(message)){ //just stop on error
    }
}
