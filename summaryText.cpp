#include "summaryText.h"

BEGIN_EVENT_TABLE(SummaryText, wxTextCtrl)
EVT_MOUSE_EVENTS(SummaryText::OnMouseEvent)
END_EVENT_TABLE()

DEFINE_EVENT_TYPE(mwEVT_SUMBOX)
//SummaryText is a text ctrl which passes mouse clicks up
void SummaryText::OnMouseEvent(wxMouseEvent& event) {
    if (event.LeftUp()) {
        // send click event to parent
        wxCommandEvent evt(mwEVT_SUMBOX, wxID_ANY);
        parentFrame->AddPendingEvent(evt);
    }
    event.Skip();
}
