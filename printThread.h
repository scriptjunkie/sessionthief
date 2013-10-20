#ifndef PRINT_THREAD_H
#define PRINT_THREAD_H

//pcap include
#include <pcap.h>
#ifndef PCAP_OPENFLAG_PROMISCUOUS
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif

//wx and std library includes
#include <wx/textctrl.h>
#include <wx/thread.h>
#include <vector>
using namespace std;

//project includes
#include "systemInterface.h"
#include "connectionInfo.h"
class nviewFrame; // can't have circular includes

DECLARE_EVENT_TYPE(mwEVT_THREAD, 67)

//thread to capture traffic, assemble HTTP requests and send them back to the main frame
class PrintThread : public wxThread {
public:
    //creation
    PrintThread(bool * capture, pcap_if_t* interf_, unsigned int targetIp_,
            nviewFrame* mainFrame_) : keepCapturing(capture), mainFrame(mainFrame_),
            interf(interf_), targetIp(targetIp_), partialGets() {};
    wxThreadError Create() {
        return wxThread::Create();
    };
private:
    //sends message to parent frame, and visualizer if present
    void sendMessage(wxString& msg, unsigned int sourceIp);
    //reassembles http requests
    bool checkComplete(wxString& input, const u_char * pkt_data, int size, int tcpHeaderOffset);
    virtual void* Entry();

    //variables
    bool * keepCapturing;//control from parent frame
    nviewFrame * mainFrame;
    pcap_if_t * interf;//interface
    unsigned int targetIp;//target
    vector<ConnectionInfo> partialGets;
};

#endif
