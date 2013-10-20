#ifndef CONNECTION_INFO_H
#define CONNECTION_INFO_H
#include <wx/string.h>

//holds a partial HTTP GET for a thread
class ConnectionInfo {
public:
    //constructors
    ConnectionInfo() { };
    ConnectionInfo(const ConnectionInfo &clone) : srcIp(clone.srcIp), dstIp(clone.dstIp),
    srcPort(clone.srcPort), dstPort(clone.dstPort), buffer(clone.buffer) {
    };
    ConnectionInfo(unsigned int srcIp_, unsigned int dstIp_,
            unsigned short srcPort_, unsigned short dstPort_, wxString &buffer_) :
    srcIp(srcIp_), dstIp(dstIp_), srcPort(srcPort_), dstPort(dstPort_), buffer(buffer_) {
    }

    //variables are public
    unsigned int srcIp;
    unsigned int dstIp;
    unsigned short srcPort;
    unsigned short dstPort;
    wxString buffer;

    //comparisons
    bool operator==(const ConnectionInfo& y) {
        return this->srcIp == y.srcIp && this->dstIp == y.dstIp 
                && this->srcPort == y.srcPort && this->dstPort == y.dstPort;
    }
    bool operator!=(const ConnectionInfo& y) {
        return !((*this) == y);
    }
    ~ConnectionInfo(){//empty destructor
    }
};

#endif
