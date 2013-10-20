#ifndef PROCESS_THREAD_H
#define PROCESS_THREAD_H

#include <wx/window.h>
#include <wx/thread.h>
#include <wx/string.h>
#include <wx/process.h>
#include <wx/stream.h>

DECLARE_EVENT_TYPE(mwEVT_PROCTHREAD, 69)

//runs a command, sending output back to main window through mwEVT_PROCTHREAD messages
class ProcessThread : public wxThread {
public:
    wxThreadError Create(const wxString& command_, bool* stillWorking_, wxWindow * parentFrame_){
        command = command_;
        stillWorking = stillWorking_;
        parentFrame = parentFrame_;
        return wxThread::Create();
    };
private:
    void output(const wxString& msg);
    wxString command;
    bool * stillWorking;
    wxWindow * parentFrame;
    virtual void* Entry();
};

#endif
