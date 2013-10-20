/*
                     .__        __     __              __   .__
  ______ ___________|__|______/  |_  |__|__ __  ____ |  | _|__| ____
 /  ___// ___\_  __ \  \____ \   __\ |  |  |  \/    \|  |/ /  |/ __ \
 \___ \\  \___|  | \/  |  |_> >  |   |  |  |  /   |  \    <|  \  ___/
/____  >\___  >__|  |__|   __/|__/\__|  |____/|___|  /__|_ \__|\___  >
     \/     \/         |__|      \______|          \/     \/       \/

 */

// reads in http request headers, puts the cookies found into the
// firefox sessionstore.js file, and launches firefox.
// compatible with firefox version 3
// no guarantees if there are preexisting cookies.

#include <wx/string.h>
#include <wx/utils.h>
#include <wx/tokenzr.h>
#include <wx/file.h>
#include <wx/textfile.h>
#include <wx/dir.h>
#include <wx/textdlg.h>
#include <vector>
using namespace std;
#include "cookieeater.h"
#include "systemInterface.h"

//user by default not given
wxString CookieEater::altUser(_T(""));
wxString CookieEater::settingsFolder = getSettingsFolder();
wxString CookieEater::ffoxExecutable = getffoxExecutable();
wxString CookieEater::ffoxArgs(_T(""));

//tries to find firefox executable and run it
wxString CookieEater::getffoxExecutable(){
    wxString winProgFiles;
    wxGetEnv(_T("ProgramFiles"), &winProgFiles); // windows?
    if (wxFile::Exists(winProgFiles + _T("\\Mozilla Firefox\\firefox.exe"))) {
        return winProgFiles + _T("\\Mozilla Firefox\\firefox.exe");
    } else { //linux, execute as specified user
        if (altUser.size() > 0)
            return _T("su ") + altUser + _T(" -c firefox");
        else
            return _T("firefox");//default
    }
}
//escapes tricky javascript characters
void CookieEater::clean(wxString& data){
    for(u_int i = 0; i < data.Len(); i++){
        if(data[i] == '\"' || data[i] == '\\' || data[i] == '\''){
            data.insert(i,_T("\\"));
            i++;
        }
    }
}

//System-specific find settings folder, outputting username if new user selected
wxString CookieEater::getSettingsFolder() {
    wxString answer = _T("");
    wxString dirname;
#ifdef WIN32
    wxGetEnv(_T("appdata"), &dirname);
    dirname += _T("\\Mozilla\\Firefox\\Profiles\\");
#else
    wxGetEnv(_T("HOME"), &dirname);
    //don't run ffox as root.
    if(dirname == _T("/root")){
        wxTextEntryDialog userChooser(NULL,_T("Please enter a username other than root to run as!")
                ,_T("User"), altUser);
        bool root = false; //keep track of whether we want to run as root
        do {
            if (userChooser.ShowModal() == wxID_CANCEL){//user may cancel and run as root
                root = true;
                break;
            }
        } while (userChooser.GetValue().Len() == 0 || !wxDir::Exists(_T("/home/") + userChooser.GetValue()));
        //if non-root user, use that
        if(!root){
            dirname.Clear();
            dirname.Append(_T("/home/")+userChooser.GetValue());
            altUser = userChooser.GetValue();
        }
    }
    dirname += _T("/.mozilla/firefox/");
#endif
    // open directory
    answer += dirname;
    wxDir directory(dirname);
    if (!directory.IsOpened())
        return answer;
    
    wxString profile; //open profile folder
    if(directory.GetFirst(&profile,wxEmptyString,wxDIR_DIRS))
        answer.append(profile);
    return answer;
}

// splits a string. Returns a new vector, which must be deleted.
vector<wxString>* CookieEater::split(const wxString& src, const wxChar * token) {
    vector<wxString>* vec = new vector<wxString>;
    unsigned int nextIndx = src.find(token, 0);
    unsigned int startIndx = 0;
    unsigned int tokenLen = wxString(token).size();
    while (nextIndx < src.Len()) {
        vec->push_back(src.substr(startIndx, nextIndx - startIndx));
        startIndx = nextIndx + tokenLen;
        nextIndx = src.find(token, startIndx);
    }
    vec->push_back(src.substr(startIndx)); // get last token
    return vec;
}

// reads host and cookies from headers, stores them in the firefox session 
// store, and starts firefox
bool CookieEater::eatCookies(const wxString & headers) {
    //if firefox is not running now
	if(CookieEater::ffoxArgs.Len() == 0 && SystemInterface::isProcessRunning(_T("firefox"))){
        wxMessageDialog dialog(NULL, _T("Exit firefox first!"), _T("Exit Firefox"),  wxOK | wxCENTER);
        dialog.ShowModal();
        return false;
    }
    
    //*************FILTER****************
    //find cookies and host in request
    wxString host;
    vector<wxString>* cookies = NULL;

	wxString line;
    unsigned int nextIndx = headers.find(_T("\r\n"), 0);
    unsigned int startIndx = 0;
    while (nextIndx < headers.Len()) {
        line = (headers.substr(startIndx, nextIndx - startIndx));
		if (line.compare(0, 8, _T("Cookie: ")) == 0) {
			cookies = split(line.substr(8), _T("; "));
		} else if (line.compare(0, 6,  _T("Host: ")) == 0) {
			// just keep last three domains, i.e. www.new.facebook.com  -> new.facebook.com
			int dotcount = 0;
			unsigned int startOfDomains = line.length();
			while (startOfDomains > 6 && dotcount < 3) {
				startOfDomains--;
				if (line[startOfDomains - 1] == '.')
					dotcount++;
			}
			host = line.substr(startOfDomains);
		}
        startIndx = nextIndx + 2;
        nextIndx = headers.find(_T("\r\n"), startIndx);
    }
    //(headers.substr(startIndx)); // ignore last token (ends with \r\n\r\n remember?)
    if (host.Len() == 0 || cookies == NULL) {
        if (cookies != NULL)
            delete cookies;
        return false;
    }

    //*************MAKE SESSION****************
    wxString session;
    clean(host);
    session += _T("({windows:[{tabs:[{entries:[{url:\"http://") + host +
            _T("\", children:[], title:\"\", ID:0}], index:0}], selected:1, _closedTabs:[], _hosts:{'")
            + host + _T("':true}, width:\"1680\", height:\"1028\", screenX:") +
            _T("\"0\", screenY:\"0\", sizemode:\"maximized\", cookies:[");
    wxString bigHost = host.substr(host.find('.'));//make cookies of parent domain
    //append each cookie
    for (unsigned int i = 0; i < cookies->size(); i++) {
        clean((*cookies)[i]);//escape out javascript junk
        //cookie looks like "__utmb=12345678"
        wxString name = (*cookies)[i].substr(0, (*cookies)[i].find('='));
        wxString value = (*cookies)[i].substr(name.size() + 1);
        if(i != 0)
            session.append(_T(", "));
        session.append(_T("{host:\"") + bigHost + _T("\", value:\"") + value + _T("\", "));
        session.append(_T("path:\"/\", name:\"") + name + _T("\"}"));
    }
    session.append(_T("]}], session:{state:\"stopped\"}})"));//starts without prompt
    delete cookies; //done with cookies

    //*************WRITE SESSION****************
    wxFile output(settingsFolder + _T("/sessionstore.js"), wxFile::write);
    if (!output.IsOpened())
        return false;
    output.Write(session);
    output.Close();

    //add user_pref("browser.sessionstore.resume_session_once", true); to prefs.js to silently start session
    wxTextFile prefs;
    if(!prefs.Open(settingsFolder + _T("/prefs.js")))
        return false;
    prefs.AddLine(_T("user_pref(\"browser.sessionstore.resume_session_once\", true);"));
    prefs.Write();
    prefs.Close();

    //*************OPEN FFOX****************
    wxExecute(ffoxExecutable+ffoxArgs);
    return true;
}
