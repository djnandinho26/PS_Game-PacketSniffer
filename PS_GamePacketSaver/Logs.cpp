#include <Windows.h>
#include <iostream>
#include <fstream>
#include <time.h>
#include <string>

using namespace std;

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;

	char       buf[80];
	localtime_s(&tstruct, &now);
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

	return buf;
}


void WriteLog(std::string text)
{
	ofstream myfile;
	myfile.open("packet.txt", std::ios_base::app | std::ios_base::out);
	myfile << currentDateTime() << " - " << text << endl;
	myfile.close();
}