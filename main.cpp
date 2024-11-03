
// This code was written as part of my learning process in network security. I
// developed it to explore potential weaknesses, such as MAC address spoofing
// and manipulating network settings, purely for educational purposes. The goal
// here was to understand how these vulnerabilities can exist in certain
// configurations and to improve my skills in identifying them.


#undef UNICODE
#undef _UNICODE

#include <objbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <wlanapi.h>
#include <string>
#include <vector>

#include <cfgmgr32.h>
#include <devguid.h>
#include <dhcpsapi.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <signal.h>
#include <iomanip>
#include <iostream>
#include <random>

#pragma comment(lib, "dhcpsapi.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")

struct NetworkInterfaceInfo {
    std::string name;
    std::string description;
    BYTE currentMac[6];
    std::string guid;
};

std::vector<NetworkInterfaceInfo> networkInterfaces;

std::string adapterName;
std::string newHostname;
enum class OperatingSystem { WINDOWS, LINUX, MACOS };

struct OSConfig {
    DWORD ttl;
    DWORD mtu;
    DWORD tcpWindowSize;
    DWORD tcpMSS;
    std::string vendorClass;
};

OSConfig GetOSConfig(OperatingSystem os) {
    OSConfig config;
    switch (os) {
    case OperatingSystem::WINDOWS:
        config.ttl = 128;
        config.mtu = 1500;  // Standard MTU
        config.tcpWindowSize = 65535;
        config.tcpMSS = 1460;             // Default MSS
        config.vendorClass = "MSFT 5.0";  // Standard for Windows
        break;

    case OperatingSystem::LINUX:
        config.ttl = 64;
        config.mtu = 1500;            // Standard MTU for ethernet networks
        config.tcpWindowSize = 5840;  // Default Linux window size
        config.tcpMSS = 1460;
        config.vendorClass = "Linux";
        break;

    case OperatingSystem::MACOS:
        config.ttl = 64;
        config.mtu = 1500;
        config.tcpWindowSize = 65535;
        config.tcpMSS = 1460;  // Standard MSS for macOS
        config.vendorClass = "Macintosh";
        break;

    default:
        // Default to Windows settings if no valid OS is provided.
        config.ttl = 128;
        config.mtu = 1500;
        config.tcpWindowSize = 65535;
        config.tcpMSS = 1460;
        config.vendorClass = "MSFT 5.0";
    }
    return config;
}
// tcp stack spoof for MSS and window size to mimick legitamate os behavior and
// reduce likelehood of fingerprint based detection from triggering
bool SetTCPStackParameters(const std::string& adapterGUID,
    DWORD windowSize,
    DWORD mss) {
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "TcpWindowSize", 0, REG_DWORD,
            (const BYTE*)&windowSize,
            sizeof(windowSize)) == ERROR_SUCCESS) {
            std::cout << "[+] TCP Window Size set to " << windowSize << std::endl;
        }
        else {
            std::cout << "[-] Failed to set TCP Window Size" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open TCP registry key" << std::endl;
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        // Another TCP property that we should spoof to ensure legit looking
        // requests
        if (RegSetValueExA(hKey, "TcpMaxSegmentSize", 0, REG_DWORD,
            (const BYTE*)&mss, sizeof(mss)) == ERROR_SUCCESS) {
            std::cout << "[+] TCP MSS set to " << mss << std::endl;
        }
        else {
            std::cout << "[-] Failed to set TCP MSS" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open TCP MSS registry key" << std::endl;
    }
    return true;
}
// debug.
void PrintHex(const char* label, const BYTE* data, int len) {
    std::cout << label << ": ";
    for (int i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
        if (i != len - 1)
            std::cout << ":";
    }
    std::cout << std::dec << std::endl;
}

// Having a legit organizational unique id  is very important, we do not want
// fortinet to detect that our mac is spoofed and not valid this is a
// combination of known vendor OUIs source:
// https://gist.github.com/aallan/b4bb86db86079509e6159810ae9bd3e4
const BYTE knownVendorOUIs[][3] = {
    {0x00, 0x1A, 0x2B}, {0x00, 0x1B, 0x21}, {0x00, 0x24, 0xD7},
    {0x00, 0x26, 0xBB}, {0xD0, 0x67, 0xE5}, {0xF0, 0x1F, 0xAF},
    {0x4C, 0x34, 0x88}, {0xAC, 0xFD, 0xEC}, {0xB8, 0x86, 0x87},
    {0x00, 0x25, 0x9C}, {0x00, 0x0C, 0x29}, {0x00, 0x50, 0x56},
    {0x1C, 0x65, 0x9D}, {0x2C, 0x56, 0xDC}, {0x00, 0x1D, 0x60},
    {0x00, 0x1C, 0xB3}, {0x00, 0x22, 0x68}, {0x00, 0x1E, 0xC9},
    {0x3C, 0xD9, 0x2B}, {0x00, 0x23, 0xAE}, {0xBC, 0x5F, 0xF4},
    {0x78, 0x4F, 0x43}, {0xC8, 0x3A, 0x35}, {0x00, 0x15, 0x5D},
    {0x00, 0x1F, 0x3B}, {0x00, 0x17, 0xA4}, {0xB0, 0x35, 0x8D},
    {0xF4, 0xB7, 0xE2}, {0x00, 0x14, 0x22}, {0x00, 0x18, 0x8B},
    {0x00, 0x0D, 0x93},
};

void GenerateRandomMAC(BYTE mac[6]) {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<> oui_dist(
        0, sizeof(knownVendorOUIs) / sizeof(knownVendorOUIs[0]) - 1);
    size_t index = oui_dist(rng);
    std::memcpy(mac, knownVendorOUIs[index],
        3);  // set the first 3 bytes to the proper oui
    for (int i = 3; i < 6; i++) {
        mac[i] = static_cast<BYTE>(rand() % 256);
    }
    mac[0] |= 0x02;  // LAA
    mac[0] &= 0xFE;  // no multicast
}

// debug for windows to make sure registry values are being read and written to.
void DumpRegistryValues(HKEY hKey, const char* subKey) {
    HKEY hSubKey;
    if (RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
        char valueName[1024];
        BYTE data[1024];
        DWORD valueNameSize = sizeof(valueName);
        DWORD dataSize = sizeof(data);
        DWORD type;
        DWORD index = 0;

        while (RegEnumValueA(hSubKey, index, valueName, &valueNameSize, NULL, &type,
            data, &dataSize) == ERROR_SUCCESS) {
            std::cout << "Registry Key: " << subKey << std::endl;
            std::cout << "Value Name: " << valueName << std::endl;
            std::cout << "Data: ";
            for (DWORD i = 0; i < dataSize; i++) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << (int)data[i];
                if (i != dataSize - 1)
                    std::cout << " ";
            }
            std::cout << std::endl;
            valueNameSize = sizeof(valueName);
            dataSize = sizeof(data);
            index++;
        }
        RegCloseKey(hSubKey);
    }
    else {
        std::cout << "Failed to open registry key: " << subKey << std::endl;
    }
}
// BYTE 6
void PrintMacAddress(const BYTE mac[6]) {
    PrintHex("MAC Address", mac, 6);
}
// write to MTU in registry

bool ChangeMTU(const std::string& adapterGUID, DWORD mtuValue) {
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "MTU", 0, REG_DWORD, (const BYTE*)&mtuValue,
            sizeof(mtuValue)) == ERROR_SUCCESS) {
            std::cout << "[+] MTU set to " << mtuValue << " [0x" << std::hex
                << mtuValue << "]" << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        else {
            std::cout << "[-] Failed to set MTU" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open MTU registry key" << std::endl;
    }
    return false;
}
// write to DefaultTTL in reg
bool SetTTL(const std::string& adapterGUID, DWORD ttlValue) {
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());
    const char* valueName = "DefaultTTL";

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, valueName, 0, REG_DWORD, (const BYTE*)&ttlValue,
            sizeof(ttlValue)) == ERROR_SUCCESS) {
            std::cout << "[+] TTL set to " << ttlValue << " [0x" << std::hex
                << ttlValue << "]" << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        else {
            std::cout << "[-] Failed to set TTL" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open TTL registry key" << std::endl;
    }
    return false;
}

// function to list all adapters in windows so we don't have to manually get the
// guid from cmd lol, im lazy
std::string GetAdapterGUID(const std::string& adapterName) {
    HKEY hKey;
    char szRegKey[1024];
    snprintf(szRegKey, sizeof(szRegKey),
        "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-"
        "BFC1-08002BE10318}");

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_READ, &hKey) !=
        ERROR_SUCCESS) {
        std::cout << "[-] Failed to open registry key" << std::endl;
        return "";
    }

    char szDataKey[256];
    for (DWORD i = 0; i < 1000; i++) {
        DWORD dataSize = sizeof(szDataKey);
        if (RegEnumKeyExA(hKey, i, szDataKey, &dataSize, NULL, NULL, NULL, NULL) !=
            ERROR_SUCCESS)
            break;

        HKEY hSubKey;
        snprintf(szRegKey, sizeof(szRegKey),
            "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-"
            "BFC1-08002BE10318}\\%s\\Connection",
            szDataKey);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_READ, &hSubKey) !=
            ERROR_SUCCESS)
            continue;

        char szName[1024];
        DWORD dwType;
        DWORD dwSize = sizeof(szName);
        if (RegQueryValueExA(hSubKey, "Name", NULL, &dwType, (LPBYTE)szName,
            &dwSize) == ERROR_SUCCESS) {
            if (adapterName == szName) {
                RegCloseKey(hSubKey);
                RegCloseKey(hKey);
                return szDataKey;
            }
        }
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hKey);
    return "";
}
// i love win32 api xd
void EnumerateAdapters() {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        std::cout << "[-] Error allocating memory for GetAdaptersInfo" << std::endl;
        return;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            std::cout << "[-] Error allocating memory for GetAdaptersInfo"
                << std::endl;
            return;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            NetworkInterfaceInfo info;
            info.name = pAdapter->AdapterName;
            info.description = pAdapter->Description;
            memcpy(info.currentMac, pAdapter->Address, 6);
            info.guid = GetAdapterGUID(info.description);
            networkInterfaces.push_back(info);
            pAdapter = pAdapter->Next;
        }
    }
    else {
        std::cout << "[-] GetAdaptersInfo failed with error: " << dwRetVal
            << std::endl;
    }

    if (pAdapterInfo)
        free(pAdapterInfo);
}
bool VerifyMACChange(const std::string& adapterName,
    const BYTE expectedMac[6]) {
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    // no admin permissions?
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        std::cout << "[-] Error allocating memory for GetAdaptersInfo" << std::endl;
        return false;
    }
    // either incorrect GUID or admin permissions
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            std::cout << "[-] Error allocating memory for GetAdaptersInfo"
                << std::endl;
            return false;
        }
    }
    // this will verify if the physical address propery in windows changed
    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (adapterName == pAdapter->AdapterName) {
                bool match = true;
                for (int i = 0; i < 6; i++) {
                    if (pAdapter->Address[i] != expectedMac[i]) {
                        match = false;
                        break;
                    }
                }
                free(pAdapterInfo);
                return match;
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    return false;
}
// reset NIC using device api, could've done this just with WMI but i think this
// approach is better for my case
bool SetDeviceEnabled(const std::string& netCfgInstanceId, bool enable) {
    HDEVINFO hDevInfo =
        SetupDiGetClassDevsA(&GUID_DEVCLASS_NET, NULL, NULL, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Failed to get device information set" << std::endl;
        return false;
    }

    SP_DEVINFO_DATA DeviceInfoData;
    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    DWORD i = 0;
    while (SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData)) {
        i++;

        HKEY hDeviceRegistryKey = SetupDiOpenDevRegKey(
            hDevInfo, &DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);

        if (hDeviceRegistryKey != INVALID_HANDLE_VALUE) {
            char szNetCfgInstanceId[256];
            DWORD dwSize = sizeof(szNetCfgInstanceId);
            DWORD dwType = 0;
            if (RegQueryValueExA(hDeviceRegistryKey, "NetCfgInstanceId", NULL,
                &dwType, (LPBYTE)szNetCfgInstanceId,
                &dwSize) == ERROR_SUCCESS) {
                if (netCfgInstanceId.compare(szNetCfgInstanceId) == 0) {
                    SP_PROPCHANGE_PARAMS propChangeParams;
                    propChangeParams.ClassInstallHeader.cbSize =
                        sizeof(SP_CLASSINSTALL_HEADER);
                    propChangeParams.ClassInstallHeader.InstallFunction =
                        DIF_PROPERTYCHANGE;
                    propChangeParams.StateChange = (enable) ? DICS_ENABLE : DICS_DISABLE;
                    propChangeParams.Scope = DICS_FLAG_GLOBAL;
                    propChangeParams.HwProfile = 0;

                    if (!SetupDiSetClassInstallParamsA(
                        hDevInfo, &DeviceInfoData,
                        &propChangeParams.ClassInstallHeader,
                        sizeof(propChangeParams))) {
                        std::cout << "[-] Failed to set class install parameters"
                            << std::endl;
                        RegCloseKey(hDeviceRegistryKey);
                        SetupDiDestroyDeviceInfoList(hDevInfo);
                        return false;
                    }

                    if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo,
                        &DeviceInfoData)) {
                        std::cout << "[-] Failed to change device state" << std::endl;
                        RegCloseKey(hDeviceRegistryKey);
                        SetupDiDestroyDeviceInfoList(hDevInfo);
                        return false;
                    }

                    RegCloseKey(hDeviceRegistryKey);
                    SetupDiDestroyDeviceInfoList(hDevInfo);
                    return true;
                }
            }
            RegCloseKey(hDeviceRegistryKey);
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    std::cout << "[-] Device not found in device info set" << std::endl;
    return false;
}
// all this function does is it will first write to NetCFGInstanceID with the
// proper adapter guid and NetworkAddress with the new mac, this will work only
// on adapters that allow mac address to be changed, some are restricted and
// only allow LAA and not global ones but there's a workaround, but for now
// atleast, this should work on most devices.
bool ChangeMAC(const std::string& adapterName, const BYTE newMac[6]) {
    char szRegKey[1024];
    snprintf(szRegKey, sizeof(szRegKey),
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-"
        "BFC1-08002BE10318}");

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, szRegKey, 0, KEY_ALL_ACCESS, &hKey) !=
        ERROR_SUCCESS) {
        std::cout
            << "[-] Failed to open registry key. Are you running as Administrator?"
            << std::endl;
        return false;
    }

    char szDataKey[256];
    for (DWORD i = 0; i < 1000; i++) {
        DWORD dataSize = sizeof(szDataKey);
        if (RegEnumKeyExA(hKey, i, szDataKey, &dataSize, NULL, NULL, NULL, NULL) !=
            ERROR_SUCCESS)
            break;

        HKEY hSubKey;
        if (RegOpenKeyExA(hKey, szDataKey, 0, KEY_ALL_ACCESS, &hSubKey) !=
            ERROR_SUCCESS)
            continue;

        char szData[1024];
        DWORD dataType;
        dataSize = sizeof(szData);
        if (RegQueryValueExA(hSubKey, "NetCfgInstanceId", NULL, &dataType,
            (LPBYTE)szData, &dataSize) == ERROR_SUCCESS) {
            if (strcmp(szData, adapterName.c_str()) == 0) {
                char newMacStr[13];
                snprintf(newMacStr, sizeof(newMacStr), "%02X%02X%02X%02X%02X%02X",
                    newMac[0], newMac[1], newMac[2], newMac[3], newMac[4],
                    newMac[5]);

                if (RegSetValueExA(hSubKey, "NetworkAddress", 0, REG_SZ,
                    (const BYTE*)newMacStr,
                    strlen(newMacStr) + 1) == ERROR_SUCCESS) {
                    std::cout << "[+] MAC address changed in registry" << std::endl;
                    std::cout << "[*] Disabling and re-enabling adapter..." << std::endl;
                    RegCloseKey(hSubKey);
                    RegCloseKey(hKey);

                    if (!SetDeviceEnabled(adapterName, false)) {
                        std::cout << "[-] Failed to disable the adapter" << std::endl;
                        return false;
                    }
                    Sleep(5000);

                    if (!SetDeviceEnabled(adapterName, true)) {
                        std::cout << "[-] Failed to enable the adapter" << std::endl;
                        return false;
                    }
                    Sleep(5000);

                    return true;
                }
                else {
                    std::cout
                        << "[-] Failed to set NetworkAddress in registry. Error code: "
                        << GetLastError() << std::endl;
                }
            }
        }
        RegCloseKey(hSubKey);
    }
    RegCloseKey(hKey);

    std::cout << "[-] Failed to find the adapter in the registry" << std::endl;
    return false;
}
// change hostname and non volatile hostname to make sure the LLMNR protocol
// doesn't leak our actual hostname!
bool ChangeNVHostname(const std::string& newHostname) {
    HKEY hKey;
    const char* subKey =
        "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
    const char* nvSubKey =
        "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, nvSubKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "ComputerName", 0, REG_SZ,
            (const BYTE*)newHostname.c_str(),
            newHostname.length() + 1) == ERROR_SUCCESS) {
            std::cout << "[+] NV Hostname changed successfully to " << newHostname
                << std::endl;
        }
        else {
            std::cout << "[-] Failed to set NV Hostname. Error code: "
                << GetLastError() << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open NV Hostname registry key" << std::endl;
        return false;
    }

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "ComputerName", 0, REG_SZ,
            (const BYTE*)newHostname.c_str(),
            newHostname.length() + 1) == ERROR_SUCCESS) {
            std::cout << "[+] Hostname changed successfully to " << newHostname
                << std::endl;
        }
        else {
            std::cout << "[-] Failed to set Hostname. Error code: " << GetLastError()
                << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open Hostname registry key" << std::endl;
        return false;
    }

    if (SetComputerNameExA(ComputerNamePhysicalDnsHostname,
        newHostname.c_str())) {
        std::cout << "[+] DNS Hostname set to " << newHostname << std::endl;
    }
    else {
        std::cout << "[-] Failed to set DNS Hostname. Error code: "
            << GetLastError() << std::endl;
        return false;
    }

    return true;
}
// flush dns, clear network stack, arp cache and profiles related to the public
// EPI network.

void FlushDNSCache() {
    system("ipconfig /flushdns > nul");
    std::cout << "[+] DNS cache flushed" << std::endl;
}

void ResetNetworkAndClearCache() {
    system("netsh interface ip delete arpcache > nul");
    system("netsh interface ip delete multicast > nul");
    // ARP cache is annoying as hell
    system("netsh winsock reset > nul");
    system("netsh int ip reset > nul");
    system("arp -d *");
    std::cout << "[+] Network stack and ARP cache reset successfully"
        << std::endl;
}

void ResetNetworkStack() {
    system("netsh winsock reset > nul");
    system("netsh int ip reset > nul");
    system("netsh wlan delete profile name=\"EPI-STUDENTS\">nul");
    system("netsh wlan delete prolfile name=\"EPI-Students\">nul");
    std::cout << "[+] Network stack reset" << std::endl;
}
// netbios is bad and very stinky and is not worth spoofing, so we will disable
// this as it will leak a lot of info
void DisableNetBIOS() {
    HKEY hKey;
    DWORD value = 2;

    if (RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char interfaceName[256];
        DWORD index = 0;
        DWORD nameSize = sizeof(interfaceName);

        while (RegEnumKeyExA(hKey, index, interfaceName, &nameSize, NULL, NULL,
            NULL, NULL) == ERROR_SUCCESS) {
            HKEY hInterfaceKey;
            if (RegOpenKeyExA(hKey, interfaceName, 0, KEY_SET_VALUE,
                &hInterfaceKey) == ERROR_SUCCESS) {
                if (RegSetValueExA(hInterfaceKey, "NetbiosOptions", 0, REG_DWORD,
                    (BYTE*)&value, sizeof(value)) == ERROR_SUCCESS) {
                    std::cout << "[+] NetBIOS disabled for interface: " << interfaceName
                        << std::endl;
                }
                else {
                    std::cout << "[-] Failed to disable NetBIOS for interface: "
                        << interfaceName << std::endl;
                }
                RegCloseKey(hInterfaceKey);
            }
            index++;
            nameSize = sizeof(interfaceName);
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open NetBIOS registry key" << std::endl;
    }
}
// DHCPDUID AND AID are 2 things that could be used to identify a blacklisted
// client so instead of bothering to spoof these we disable it lol
void DisableIPv6() {
    HKEY hKey;
    DWORD value = 0xffffffff;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "DisabledComponents", 0, REG_DWORD, (BYTE*)&value,
            sizeof(value)) == ERROR_SUCCESS) {
            std::cout << "[+] IPv6 disabled successfully" << std::endl;
        }
        else {
            std::cout << "[-] Failed to disable IPv6" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open IPv6 registry key" << std::endl;
    }
}
// this doesn't work on windows 11 23H2 but might work on older builds, juste
// 3la mayati disable it
void DisableLLMNR() {
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
    DWORD disable = 1;

    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey,
        NULL) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "EnableMulticast", 0, REG_DWORD,
            (const BYTE*)&disable,
            sizeof(disable)) == ERROR_SUCCESS) {
            std::cout << "[+] LLMNR disabled successfully" << std::endl;
        }
        else {
            std::cout << "[-] Failed to disable LLMNR" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to create or open DNSClient registry key"
            << std::endl;
    }
}
// no network discovery and file shraring and printer sharing, we don't want any
// kind of SMB related protocols to be leaking our info now do we.
void DisableNetworkDiscovery() {
    system(
        "netsh advfirewall firewall set rule group=\"Network Discovery\" new "
        "enable=No profile=private > nul");
    system(
        "netsh advfirewall firewall set rule group=\"Network Discovery\" new "
        "enable=No profile=public > nul");
    system(
        "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" "
        "new enable=No profile=private > nul");
    system(
        "netsh advfirewall firewall set rule group=\"File and Printer Sharing\" "
        "new enable=No profile=public > nul");
    std::cout << "[+] Network Discovery and File Sharing disabled" << std::endl;
    system(
        "netsh advfirewall firewall add rule name=\"Block mDNS\" dir=out "
        "action=block protocol=UDP remoteport=5353 > nul");
    std::cout << "[+] mDNS disabled (firewall rule added)" << std::endl;
    system(
        "netsh advfirewall firewall add rule name=\"Block IGMP\" dir=out "
        "action=block protocol=2 > nul");
    std::cout << "[+] IGMP disabled (firewall rule added)" << std::endl;
}
void FlushSSDPAndDisableUPnP() {
    system("net stop SSDPSRV > nul");
    std::cout << "[+] SSDP Discovery service stopped" << std::endl;
    system("sc config upnphost start= disabled > nul");
    std::cout << "[+] UPnP Device Host service disabled" << std::endl;
    system(
        "netsh advfirewall firewall add rule name=\"Block SSDP\" dir=out "
        "action=block protocol=UDP remoteport=1900 > nul");
    std::cout << "[+] SSDP blocked (firewall rule added)" << std::endl;
}
void EnhanceNetworkProtection() {
    DisableNetBIOS();
    DisableIPv6();
    DisableNetworkDiscovery();
    DisableLLMNR();
    FlushSSDPAndDisableUPnP();
}

std::string GenerateRandomString(int length, const std::string& charset) {
    std::string result;
    for (int i = 0; i < length; ++i) {
        result += charset[rand() % charset.size()];
    }
    return result;
}

// We set the DHCP Client Identifier (Option 61) to a random string for IPv4
// requests. routers may not rely on this option and will only process the core
// DHCP frame related to client identification (normally) However by spoofing
// key identifiers (like MAC address, Client Identifier, and hostname), we
// ensure that the DHCP request appears as a legitimate new client.

bool SetDHCPClientIdentifier(const std::string& adapterGUID) {
    std::string randomId = GenerateRandomString(12, "0123456789ABCDEF");
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "DhcpClientIdentifier", 0, REG_SZ,
            (const BYTE*)randomId.c_str(),
            randomId.length() + 1) == ERROR_SUCCESS) {
            std::cout << "[+] DHCP Client Identifier set to " << randomId
                << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        else {
            std::cout << "[-] Failed to set DHCP Client Identifier." << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open DHCP registry key" << std::endl;
    }
    return false;
}
// vendor class identifier spoof not sent by default but we spoof to make sure
// even with specific config changes.
bool SetVendorClassIdentifier(const std::string& adapterGUID,
    const std::string& vendorClass) {
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "VendorClassId", 0, REG_SZ,
            (const BYTE*)vendorClass.c_str(),
            vendorClass.length() + 1) == ERROR_SUCCESS) {
            std::cout << "[+] Vendor Class Identifier set to " << vendorClass
                << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        else {
            std::cout << "[-] Failed to set Vendor Class Identifier" << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open Vendor Class Identifier registry key"
            << std::endl;
    }
    return false;
}
bool SpoofDHCPParameterRequestList(const std::string& adapterGUID) {
    std::string randomList =
        GenerateRandomString(8, "0123456789ABCDEF");  // Craft the request
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "DhcpRequestList", 0, REG_SZ,
            (const BYTE*)randomList.c_str(),
            randomList.length() + 1) == ERROR_SUCCESS) {
            std::cout << "[+] DHCP Parameter Request List spoofed." << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        else {
            std::cout << "[-] Failed to spoof DHCP Parameter Request List."
                << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open DHCP registry key." << std::endl;
    }
    return false;
}
bool SpoofHostname(const std::string& adapterGUID,
    const std::string& spoofedHostname) {
    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_ALL_ACCESS, &hKey) ==
        ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "HostName", 0, REG_SZ,
            (const BYTE*)spoofedHostname.c_str(),
            spoofedHostname.length() + 1) == ERROR_SUCCESS) {
            std::cout << "[+] Hostname spoofed to " << spoofedHostname << std::endl;
            RegCloseKey(hKey);
            return true;
        }
        else {
            std::cout << "[-] Failed to spoof Hostname." << std::endl;
        }
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open Hostname registry key" << std::endl;
    }
    return false;
}
// now we combine all these steps into a consice procedure that will set
// everything based on the operating system we select.
void SpoofNetworkSettings(const std::string& adapterGUID, OperatingSystem os) {
    OSConfig config = GetOSConfig(os);

    if (config.vendorClass == "MSFT 5.0") {
        config.ttl = 128;
        std::cout << "[*] Forcing TTL to 128 for Windows (MSFT 5.0)" << std::endl;
    }

    if (SetTTL(adapterGUID, config.ttl)) {
        std::cout << "[+] TTL set to " << config.ttl << std::endl;
    }
    else {
        std::cout << "[-] Failed to set TTL" << std::endl;
    }

    if (ChangeMTU(adapterGUID, config.mtu)) {
        std::cout << "[+] MTU set to " << config.mtu << std::endl;
    }
    else {
        std::cout << "[-] Failed to set MTU" << std::endl;
    }
    if (SetVendorClassIdentifier(adapterGUID, config.vendorClass)) {
        std::cout << "[+] Vendor Class Identifier set to " << config.vendorClass
            << std::endl;
    }
    else {
        std::cout << "[-] Failed to set Vendor Class Identifier" << std::endl;
    }
    if (SpoofDHCPParameterRequestList(adapterGUID)) {
        std::cout << "[+] Spoofed request list. " << std::endl;
    }
    else {
        std::cout << "[+] Failed Spoofed request list. " << std::endl;
    }
    if (SetTCPStackParameters(adapterGUID, config.tcpWindowSize, config.tcpMSS)) {
        std::cout << "Set TCP stack params" << std::endl;
    }
}
void CurrentSet(const std::string& adapterGUID) {
    std::cout << "[+] Released DHCP lease for adapter: " << adapterName
        << std::endl;

    HKEY hKey;
    char subKey[512];
    snprintf(
        subKey, sizeof(subKey),
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey) ==
        ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "Lease");
        RegDeleteValueA(hKey, "LeaseObtainedTime");
        RegDeleteValueA(hKey, "LeaseTerminatesTime");
        RegDeleteValueA(hKey, "DhcpIPAddress");
        RegDeleteValueA(hKey, "DhcpSubnetMask");
        RegDeleteValueA(hKey, "DhcpServer");
        RegDeleteValueA(hKey, "DhcpDefaultGateway");
        std::cout << "[+] Old DHCP lease records cleared." << std::endl;
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open registry key to clear old DHCP leases."
            << std::endl;
    }
}

// some caching happens in 001 so we deal with this too, don't know why but ok
// windows.
void currentSet001(const std::string& adapterGUID) {
    std::cout << "[+] Released DHCP lease for adapter: " << adapterName
        << std::endl;

    HKEY hKey;
    char subKey[512];
    snprintf(subKey, sizeof(subKey),
        "SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces\\%s",
        adapterGUID.c_str());

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey) ==
        ERROR_SUCCESS) {
        RegDeleteValueA(hKey, "Lease");
        RegDeleteValueA(hKey, "LeaseObtainedTime");
        RegDeleteValueA(hKey, "LeaseTerminatesTime");
        RegDeleteValueA(hKey, "DhcpIPAddress");
        RegDeleteValueA(hKey, "DhcpSubnetMask");
        RegDeleteValueA(hKey, "DhcpServer");
        RegDeleteValueA(hKey, "DhcpDefaultGateway");
        std::cout << "[+] Old DHCP lease records cleared." << std::endl;
        RegCloseKey(hKey);
    }
    else {
        std::cout << "[-] Failed to open registry key to clear old DHCP leases."
            << std::endl;
    }
}
int main() {
    srand(static_cast<unsigned int>(time(NULL)));
    std::string choicez;
    std::cout << "==================================" << std::endl;
    std::cout << "           FortiPhantom           " << std::endl;
    std::cout << "==================================" << std::endl;
    std::cout << "            By Zeph\n             " << std::endl;

    OperatingSystem spoofedOS = OperatingSystem::WINDOWS;  // good ol windows
    OSConfig config = GetOSConfig(spoofedOS);
    char hostnameBuffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameSize = sizeof(hostnameBuffer);
    if (GetComputerNameA(hostnameBuffer, &hostnameSize)) {
        std::cout << "[*] Original Hostname: " << hostnameBuffer << std::endl;
    }
    else {
        std::cout << "[-] Failed to get original hostname" << std::endl;
        return 1;
    }

    EnumerateAdapters();

    if (networkInterfaces.empty()) {
        std::cout << "[-] No network adapters found" << std::endl;
        return 1;
    }

    std::cout << "\n[*] Available network adapters:" << std::endl;
    for (size_t i = 0; i < networkInterfaces.size(); ++i) {
        std::cout << "   " << i + 1 << ". " << networkInterfaces[i].description
            << std::endl;
        std::cout << "      Current MAC: ";
        PrintMacAddress(networkInterfaces[i].currentMac);
    }

    size_t choice;
    do {
        std::cout << "\nEnter the number of the adapter you want to change (1-"
            << networkInterfaces.size() << "): ";
        std::cin >> choice;
    } while (choice < 1 || choice > networkInterfaces.size());

    const NetworkInterfaceInfo& selectedAdapter = networkInterfaces[choice - 1];
    adapterName = selectedAdapter.name;
    std::string adapterGUID = selectedAdapter.guid;

    BYTE newMac[6];
    GenerateRandomMAC(newMac);
    system("ipconfig /release > nul");

    std::cout << "\n[*] Changing MAC address for " << selectedAdapter.description
        << std::endl;
    std::cout << "[*] New MAC: ";
    PrintMacAddress(newMac);

    if (ChangeMAC(selectedAdapter.name, newMac)) {
        if (VerifyMACChange(selectedAdapter.name, newMac)) {
            std::cout << "[+] MAC addresds successfully changed and verified"
                << std::endl;
        }
        else {
            std::cout
                << "[-] MAC address change was attempted, but verification failed"
                << std::endl;
        }
    }
    else {
        std::cout << "[-] Failed to change MAC address" << std::endl;
    }

    std::string spoofedHostname =
        GenerateRandomString(8, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    SpoofHostname(adapterGUID, spoofedHostname);
    ChangeNVHostname(spoofedHostname);
    SetDHCPClientIdentifier(adapterGUID);

    SpoofNetworkSettings(adapterGUID, spoofedOS);
    CurrentSet(adapterGUID);
    currentSet001(adapterGUID);
    FlushDNSCache();
    ResetNetworkAndClearCache();
    ResetNetworkStack();
    EnhanceNetworkProtection();

    std::cout << "\n[+] Your pc now identifies as a toaster!" << std::endl;

    std::cout << "\nDo you want to restart your PC now? (y/n): ";
    std::cin >> choicez;

    if (choicez == "y" || choicez == "Y") {
        system("shutdown /r /t 0");
    }
    else {
        std::cout << "[*] Restart skipped. Remember to restart manually for "
            "changes to take full effect."
            << std::endl;
    }

    return 0;
}
