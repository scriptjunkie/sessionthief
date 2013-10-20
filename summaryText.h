#ifndef SUMMARY_TEXT_H
#define SUMMARY_TEXT_H

#include "nviewFrame.h"

DECLARE_EVENT_TYPE(mwEVT_SUMBOX, 68)

// a text ctrl which passes mouse clicks up
class SummaryText : public wxTextCtrl {
public:
	SummaryText(nviewFrame *parent, wxWindowID id, const wxString &value, const wxPoint &pos, 
			const wxSize &size, int style = 0) : wxTextCtrl(parent, id, value, pos, size, style) {
		parentFrame = parent;
	}
	// passes mouse clicks on
	void OnMouseEvent(wxMouseEvent& event);
private:
	nviewFrame * parentFrame;
	DECLARE_EVENT_TABLE()
};

#endif
