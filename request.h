#ifndef REQUEST_H
#define REQUEST_H

#include <wx/string.h>
using namespace std;

// holds one HTTP header
class Request {
public:
	wxString HTTP;
	wxString URL;
	unsigned int IP;
	//create a Request object from a request string and ip
	Request(wxString & get, unsigned int ip);
	//create a Request object with http, url, and ip known
	Request(wxString & http, wxString & url, unsigned int ip):HTTP(http),URL(url),IP(ip) {
	}
	//create a Request object from another
	Request(const Request &clone) : HTTP(clone.HTTP), URL(clone.URL), IP(clone.IP){
	}
	~Request() {
	}
};
#endif
