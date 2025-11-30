// strace2rdf.cpp : This file contains the 'main' function_name. Program execution begins and ends there.
//

//#include <iostream>

import std;
import straceparser;

using namespace std;

/*
    print("DockIT: %s <executable>" % prog_nam)
    print("Monitors and factorizes systems calls.")
    print("  -h,--help                       This message.")
    print("  -v,--verbose                    Verbose mode (Cumulative).")
    print("  -w,--warning                    Displays warnings (Cumulative).")
    print("  -s,--summary <CIM class>        Prints a summary at the end: Start end end time stamps, executable name,\n"
        + "                                  loaded libraries, read/written/created files and timestamps, subprocesses tree.\n"
        + "                                  Examples: -s 'Win32_LogicalDisk.DeviceID=\"C:\",Prop1=\"Value1\",Prop2=\"Value2\"'\n"
        + "                                            -s 'CIM_DataFile:Category=[\"Others\",\"Shared libraries\"]'" )
    print("  -D,--dockerfile                 Generates a dockerfile.")
    print("  -M,--makefile <makefile name>   Generates a makefile.")
    print("  -p,--pid <pid>                  Monitors a running process instead of starting an executable.")
    print("  -f,--format TXT|CSV|JSON        Output format. Default is TXT.")
    print("  -F,--summary-format TXT|XML     Summary output format. Default is XML.")
    print("  -i,--input <file name>          Trace input log file for replaying a session.")
    print("  -l,--log <filename prefix>      Directory and prefix of output files.")
    print("  -t,--tracer strace|ltrace|pydbg Set trace program.")
    print("  -S,--server <Url>               Survol url for CIM objects updates. Ex: http://127.0.0.1:80/survol/event_put.py")
    print("  -a,--aggregator <aggregator>    Aggregation method, e.g. 'clusterize' etc...")
    print("  -d,--log                        Duplicates session to a log file which can be replayed as input.")

    print("")
*/

/*
* On va uniquement parser strace.
*/


int main()
{
    string filename;
    STraceParser parser(filename);

    for (;;) {
        const auto & [tripleStoreStatus, triplestoreRef] = parser.get_next_triplestore();
        if (tripleStoreStatus == Line::LineState::EndOfFile) {
            break;
        }
        switch (tripleStoreStatus) {
            case Line::LineState::Unsupported:
                continue;
            case Line::LineState::Normal:
                triplestoreRef.display();
                break;
            case Line::LineState::Resumed:
                continue;
            default:
                throw runtime_error("Invalid code");
        }
    }

    std::cout << "Hello World!\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
