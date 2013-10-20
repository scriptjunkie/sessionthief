#if defined(__GNUG__) && !defined(__APPLE__)
#pragma implementation "netrstproj.h"
#endif

#include "sessionApp.h"
// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"
#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif
#include <wx/url.h>
#ifdef WIN32
#include <wx/msw/registry.h>
#include <wx/buffer.h>
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
	checkUpdate();
	nviewFrame* mainWindow = new nviewFrame(NULL, netView);
	mainWindow->Show(true);
	return true;
}

// Checks for updates, every week on Windows
void SessionApp::checkUpdate(){
#ifdef WIN32
	ULARGE_INTEGER ul;
	ULARGE_INTEGER lastul;
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	ul.LowPart = ft.dwLowDateTime;
	ul.HighPart = ft.dwHighDateTime;
	wxMemoryBuffer lastAccessed;

	wxRegKey *pRegKey = new wxRegKey(_T("HKEY_CURRENT_USER\\Software\\sessionthief"));
	//will create the Key if it does not exist
	if( !pRegKey->Exists() )
		pRegKey->Create();
	if(pRegKey->HasValue(_T("vertime"))){
		//Get last accessed time
		pRegKey->QueryValue(_T("vertime"),lastAccessed);
		if(lastAccessed.GetDataLen() == sizeof(lastul)){
			memcpy(&lastul, lastAccessed.GetData(), sizeof(lastul));
			if((ul.QuadPart - lastul.QuadPart)/1000000 < 6048000) // (1 week) / (100 nanoseconds) = 6 048 000 000 000
				return;
		}
	}
#endif
	//Read update URL, make sure 
	wxURL updateURL(_T("http://www.scriptjunkie.us/files/stver"));
	wxInputStream * updateStream = updateURL.GetInputStream();
	if(updateStream != NULL){
		unsigned int magic, ver;
		updateStream->Read(&magic,4);
		if(updateStream->LastRead() != 4 || magic != 0x4ea3fbc2)
			return;
		updateStream->Read(&ver,4);
		if(updateStream->LastRead() != 4)
			return;
		if(ver > VERSION)
			wxMessageBox(_T("A newer version of sessionthief is available!\nSee http://www.scriptjunkie.us/sessionthief.zip"));
#ifdef WIN32
		//Update last check time
		lastAccessed.SetDataLen(0);
		lastAccessed.AppendData(&ul, sizeof(ul));
		pRegKey->SetValue(_T("vertime"),lastAccessed);
		pRegKey->Close();
#endif
	}
}

// Cleanup for SessionApp
int SessionApp::OnExit() {
	return wxApp::OnExit();
}
