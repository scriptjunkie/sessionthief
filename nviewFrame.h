#ifndef _NVIEWFRAME_H_
#define _NVIEWFRAME_H_

#if defined(__GNUG__) && !defined(__APPLE__)
#pragma interface "nviewFrame.cpp"
#endif

//platform specific includes
#ifdef WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#endif

//wx includes
#include <wx/wxprec.h>
#ifndef WX_PRECOMP
#include <wx/wx.h>
#endif
#include <wx/aboutdlg.h>
#include <wx/button.h>
#include <wx/file.h>
#include <wx/frame.h>
#include <wx/menu.h>
#include <wx/process.h>
#include <wx/stattext.h>
#include <wx/stream.h>
#include <wx/textctrl.h>
#include <wx/textdlg.h>

// Compatibility
#ifndef wxCLOSE_BOX
#define wxCLOSE_BOX 0x1000
#endif
#ifndef wxFIXED_MINSIZE
#define wxFIXED_MINSIZE 0
#endif

//pcap and project includes
#include <pcap.h>
#include "systemInterface.h"
#include "arp.h"
#include "processThread.h"
#include "printThread.h"
#include "request.h"
#include "cookieeater.h"

enum { // control ID's
	netView,
	txtView,
	txtSummary,
	passiveMenu,
	watchButton,
	txtIp,
	aprMenuId,
	blockMenu,
	activeMenu,
	restoreMenu,
	cookieButton,
	interfaceMenu,
	portMenu,
	firefoxSelectMenu,
	profileSelectMenu,
	label1ID,
	label2ID,
	clearButton
};

// nviewFrame class declaration
class nviewFrame : public wxFrame {
	DECLARE_CLASS(nviewFrame)
	DECLARE_EVENT_TABLE()

public:
	/// Constructor
	nviewFrame(wxWindow* parent, wxWindowID id = netView, const wxString& caption = 
		_T("Session Thief"), const wxPoint& pos = wxDefaultPosition, const 
		wxSize& size = wxSize(800, 500), long style = wxDEFAULT_FRAME_STYLE);

	// Destructor
	~nviewFrame();

	/// Creates the controls and sizers
	void CreateControls();

	// menu and button event handlers
	void OnPassiveMenuClick(wxCommandEvent& event);
	void OnBlockMenuClick(wxCommandEvent& event);
	void OnrestoreMenuClick(wxCommandEvent& event);
	void OnCookiebuttonClick(wxCommandEvent& event);
	void OninterfaceMenuClick(wxCommandEvent& event);
	void OnportMenuClick(wxCommandEvent& event);
	void OnFirefoxMenuClick(wxCommandEvent& event);
	void OnProfileMenuClick(wxCommandEvent& event);
	void OnWatchbuttonClick(wxCommandEvent& event);
	void OnAprMenuClick(wxCommandEvent& event);
	void OnActiveMenuClick(wxCommandEvent& event);
	void OnAboutMenuClick(wxCommandEvent& event);
	void OnClearbuttonClick(wxCommandEvent& event);

	// message event handler
	void GetPrintThreadMessage(wxCommandEvent& event);
	// text click event handler
	void OnTextSumBoxClick(wxCommandEvent& event);
	//process thread output
	void GetProcThreadMessage(wxCommandEvent& event);

	/// wx junk
	wxBitmap GetBitmapResource(const wxString& name);
	wxIcon GetIconResource(const wxString& name);

	/// Should we show tooltips?
	static bool ShowToolTips() {
		return TRUE;
	}
private:
	//helper functions
	void PrintProcess(const wxString& command);
	void getNewInterface();
	//controls
	wxTextCtrl* textBox;
	wxTextCtrl* textSumBox;
	wxTextCtrl* ipBox;
	wxButton* clearButtonControl;
	wxButton* cookieButtonControl;
	wxButton* watchButtonControl;
	wxMenu *setupMenu;
	wxMenu *discoverMenu;
	wxMenu *aprMenu;
	wxMenu *helpMenu;

	//member data
	bool aprRunning; // apr info
	bool processRunning; // for process
	pcap_if_t* interf;
	bool captureTcp;
	vector<Request> requests; //stored HTTP
};

#endif
// _NVIEWFRAME_H_
