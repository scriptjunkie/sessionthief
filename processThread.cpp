#include <wx/event.h>

#include "processThread.h"

DEFINE_EVENT_TYPE(mwEVT_PROCTHREAD)

//main thread function; runs process
wxThread::ExitCode ProcessThread::Entry() {
	*stillWorking = true;
	// get input
	wxProcess* proc = wxProcess::Open(command);
	output(command);
	if(proc == NULL){
		output( _T("ERROR CANNOT RUN ") + command + _T("\n"));
		*stillWorking = false;
		return 0;
	}
	wxInputStream* is = proc->GetInputStream();
	// push through until end
	char buf[128];
	while(!is->Eof()){
		is->Read(buf,128);
		output(wxString::FromUTF8(buf,is->LastRead()));
	}
	// we're done
	*stillWorking = false;
	return 0;
}// end Entry()  [prints process output]
//simplified output; sends event to main thread
void ProcessThread::output(const wxString& msg) {
	wxCommandEvent evt(mwEVT_PROCTHREAD, wxID_ANY);
	evt.SetString(msg);
	parentFrame->GetEventHandler()->AddPendingEvent(evt);
}
