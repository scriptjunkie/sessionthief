#if defined(__GNUG__) && !defined(__APPLE__)
#pragma implementation "netrstproj.h"
#endif

#include "sessionApp.h"
// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"
#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

// Application instance implementation
IMPLEMENT_APP(SessionApp)

// SessionApp type definition
IMPLEMENT_CLASS(SessionApp, wxApp)

// SessionApp event table definition
BEGIN_EVENT_TABLE(SessionApp, wxApp)
END_EVENT_TABLE()

// Constructor for SessionApp
SessionApp::SessionApp() { }

// APPLICATION ENTRY POINT
bool SessionApp::OnInit() {
    nviewFrame* mainWindow = new nviewFrame(NULL, netView);
    mainWindow->Show(true);
    return true;
}

// Cleanup for SessionApp
int SessionApp::OnExit() {
    return wxApp::OnExit();
}
