#include <Windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include "tclap/CmdLine.h"

extern BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

int main(int argc, char *argv[])
{
#ifdef _BUILD32
#define _PACKAGENAME "packer32"
#else
#define _PACKAGENAME "packer64"
#endif

	TCLAP::CmdLine cmdline(_PACKAGENAME, ' ', "0.4");
	
	TCLAP::ValueArg<std::string> inputFile("i", "infile", "Input file", true, "homer", "filename");
	TCLAP::ValueArg<std::string> outputFile("o", "outfile", "Output file", false, "homer", "filename");
	TCLAP::ValueArg<std::string> verbose("v", "verbose", "Verbose output", false, "", "");

	cmdline.add(inputFile);
	cmdline.add(outputFile);
	cmdline.add(verbose);
	
	//cmdline.parse(argc, argv);
	//cmdline.parse(argc, argv);

#ifdef _BUILD32
	extern int main32(int, char*argv[]);
	extern int unpack32(int, char*argv[]);

	if (argv[1][0] == '-' && argv[1][1] == 'u')
		return unpack32(argc, argv);
	else
		return main32(argc, argv);
#else
	extern int main64(int argc, char *argv[]);
	return main64(argc, argv);
#endif


}
