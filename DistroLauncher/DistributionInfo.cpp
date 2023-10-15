//
//    Copyright (C) Microsoft.  All rights reserved.
// Licensed under the terms described in the LICENSE file in the root of this project.
//

#include "stdafx.h"

bool DistributionInfo::CreateUser(std::wstring_view userName)
{
    // Create the user account.
    DWORD exitCode;
    std::wstring commandLine = L"/usr/sbin/useradd -m -U -G adm,wheel ";
    commandLine += userName;
    HRESULT hr = g_wslApi.WslLaunchInteractive(commandLine.c_str(), true, &exitCode);
    if ((FAILED(hr)) || (exitCode != 0)) {
        return false;
    }

    commandLine = L"/usr/bin/passwd ";
    commandLine += userName;
    const wchar_t* passwd = commandLine.c_str();
    do
    {
        hr = g_wslApi.WslLaunchInteractive(passwd, true, &exitCode);
    } while ((FAILED(hr)) || (exitCode != 0));

    // Now do hacky thing to set root password with info

    commandLine = L"/usr/bin/echo 'Setup an root password' && /usr/bin/passwd ";
    commandLine += L"root";
    const wchar_t* rootpasswd = commandLine.c_str();
    do
    {
        hr = g_wslApi.WslLaunchInteractive(rootpasswd, true, &exitCode);
    } while ((FAILED(hr)) || (exitCode != 0));

    commandLine = L"/usr/bin/echo 'Remember to enable nonroot users in sudoers file who have wheel group' ";
    commandLine += L"&& /usr/bin/echo 'Until then use su root to login into root account so you can make needed changes in the rootfs'";
    const wchar_t* addinfo = commandLine.c_str();
    do
    {
        hr = g_wslApi.WslLaunchInteractive(addinfo, true, &exitCode);
    } while ((FAILED(hr)) || (exitCode != 0));

    return true;
}

ULONG DistributionInfo::QueryUid(std::wstring_view userName)
{
    // Create a pipe to read the output of the launched process.
    HANDLE readPipe;
    HANDLE writePipe;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, true};
    ULONG uid = UID_INVALID;
    if (CreatePipe(&readPipe, &writePipe, &sa, 0)) {
        // Query the UID of the supplied username.
        std::wstring command = L"/usr/bin/id -u ";
        command += userName;
        int returnValue = 0;
        HANDLE child;
        HRESULT hr = g_wslApi.WslLaunch(command.c_str(), true, GetStdHandle(STD_INPUT_HANDLE), writePipe, GetStdHandle(STD_ERROR_HANDLE), &child);
        if (SUCCEEDED(hr)) {
            // Wait for the child to exit and ensure process exited successfully.
            WaitForSingleObject(child, INFINITE);
            DWORD exitCode;
            if ((GetExitCodeProcess(child, &exitCode) == false) || (exitCode != 0)) {
                hr = E_INVALIDARG;
            }

            CloseHandle(child);
            if (SUCCEEDED(hr)) {
                char buffer[64];
                DWORD bytesRead;

                // Read the output of the command from the pipe and convert to a UID.
                if (ReadFile(readPipe, buffer, (sizeof(buffer) - 1), &bytesRead, nullptr)) {
                    buffer[bytesRead] = ANSI_NULL;
                    try {
                        uid = std::stoul(buffer, nullptr, 10);

                    } catch( ... ) { }
                }
            }
        }

        CloseHandle(readPipe);
        CloseHandle(writePipe);
    }

    return uid;
}
