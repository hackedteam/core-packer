#include <Windows.h>
#include <iostream>
#include <string>
#include <algorithm>
#include "tclap/CmdLine.h"

extern BOOL WINAPI DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

int main(int argc, char *argv[])
{
#ifdef _BUILD32
	TCLAP::CmdLine cmdline("packer32", ' ', "0.4");
	
	TCLAP::ValueArg<std::string> inputFile("i", "infile", "Input file", true, "homer", "filename");
	TCLAP::ValueArg<std::string> outputFile("o", "outfile", "Output file", false, "homer", "filename");

	cmdline.add(inputFile);
	cmdline.add(outputFile);

	//cmdline.parse(argc, argv);

	extern int main32(int, char*argv[]);
	return main32(argc, argv);
#else
	TCLAP::CmdLine cmdline("packer64", ' ', "0.4");
	
	TCLAP::ValueArg<std::string> inputFile("i", "infile", "Input file", true, "homer", "filename");
	TCLAP::ValueArg<std::string> outputFile("o", "outfile", "Output file", false, "homer", "filename");

	cmdline.add(inputFile);
	cmdline.add(outputFile);

	//cmdline.parse(argc, argv);

	extern int main64(int argc, char *argv[]);
	return main64(argc, argv);
#endif

}
