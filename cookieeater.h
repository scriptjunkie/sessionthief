/*
					 .__		__	 __			  __   .__
  ______ ___________|__|______/  |_  |__|__ __  ____ |  | _|__| ____
 /  ___// ___\_  __ \  \____ \   __\ |  |  |  \/	\|  |/ /  |/ __ \
 \___ \\  \___|  | \/  |  |_> >  |   |  |  |  /   |  \	<|  \  ___/
/____  >\___  >__|  |__|   __/|__/\__|  |____/|___|  /__|_ \__|\___  >
	 \/	 \/		 |__|	  \______|		  \/	 \/	   \/

 */

// reads in http request headers, puts the cookies found into the
// firefox sessionstore.js file, and launches firefox.

// compatible with firefox version 3

// no guarantees if there are preexisting cookies.

#ifndef _COOKIEEATER_H
#define	_COOKIEEATER_H

#include <wx/string.h>
#include <vector>
using namespace std;

//cookie eater class. Mostly static
class CookieEater{
public:
	static bool eatCookies(const wxString & headers);
	static vector<wxString>* split(const wxString& src, const wxChar * token);

	static wxString settingsFolder;
	static wxString ffoxExecutable;
//	static wxString ffoxArgs;
private:
	static wxString altUser;
	static void clean (wxString& data);//escapes quotes, etc in data
	static wxString getffoxExecutable();
	static wxString getSettingsFolder();
};

#endif
