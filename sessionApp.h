#ifndef _NETRSTPROJ_H_
#define _NETRSTPROJ_H_

#include "nviewFrame.h"

#if defined(__GNUG__) && !defined(__APPLE__)
#pragma interface "netrstproj.cpp"
#endif

#include <wx/app.h>

// Application class declaration
class SessionApp: public wxApp {
    DECLARE_CLASS( SessionApp );
    DECLARE_EVENT_TABLE();
public:
    // Constructor
    SessionApp();

    // Start of the application
    virtual bool OnInit();

    // Called on exit
    virtual int OnExit();
};

// Application instance declaration
DECLARE_APP(SessionApp);

#endif
