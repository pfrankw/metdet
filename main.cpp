#include <windows.h>
#include "polarssl/polarssl/net.h"
#include "polarssl/polarssl/base64.h"
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
using namespace std;




// To ensure correct resolution of symbols, add Psapi.lib to TARGETLIBS
// and compile with -DPSAPI_VERSION=1

char *char2hex( char dec, char *result)
{
    char dig1 = (dec&0xF0)>>4;
    char dig2 = (dec&0x0F);
    if ( 0<= dig1 && dig1<= 9) dig1+=48;    //0,48inascii
    if (10<= dig1 && dig1<=15) dig1+=97-10; //a,97inascii
    if ( 0<= dig2 && dig2<= 9) dig2+=48;
    if (10<= dig2 && dig2<=15) dig2+=97-10;

    strncat(result, &dig1, 1);
    strncat(result, &dig2, 1);
    return result;
}

char *urlencode(char *c, char *result, size_t size_result)
{
    if(size_result <=0 || !result)
        return result;

    result[0]=0;
    char tmp[10];
    size_t n = strlen(c);
    for(size_t i=0, x=0;i<n && x<size_result; i++)
    {
        if ( (48 <= c[i] && c[i] <= 57) ||//0-9
             (65 <= c[i] && c[i] <= 90) ||//abc...xyz
             (97 <= c[i] && c[i] <= 122) || //ABC...XYZ
             (c[i]=='~' || c[i]=='!' || c[i]=='*' || c[i]=='(' || c[i]==')' || c[i]=='\'')
        )
        {
            strncat(result, &c[i], 1);
            x++;
        }
        else if( (x+3)<=size_result)
        {
            strncat(result, "%", 1);
            char2hex(c[i], result);
            x+=3;
        }

    }
    return result;
}





BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if ( !LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup
            &luid ) )        // receives LUID of privilege
    {
        printf("[-] LookupPrivilegeValue error: %u\n", GetLastError() );
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges(
           hToken,
           FALSE,
           &tp,
           sizeof(TOKEN_PRIVILEGES),
           (PTOKEN_PRIVILEGES) NULL,
           (PDWORD) NULL) )
    {
          printf("[-] AdjustTokenPrivileges error: %u\n", GetLastError() );
          return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("[-] The token does not have the specified privilege. \n");
          return FALSE;
    }

    return TRUE;
}


void signal_cec(char *procpath, DWORD pid, char* pcname)
{
    int fd = 0;
    if(net_connect(&fd, "host", 80)==0)
    {
        FILE *fp;
        char *request = new char[4096];


        char tmp_path[260], tmp_pcname[250];

        urlencode(procpath, tmp_path, 260);
        urlencode(pcname, tmp_pcname, 250);

        sprintf(request, "GET /detection.php?process_path=%s&process_id=%d&computer_name=%s HTTP/1.1\r\n"
                "Host: host\r\n"
                "Accept: */*\r\n"
                "User-Agent: Metdet-Analyzer\r\n"
                "Connection: close\r\n"
                "\r\n", tmp_path, pid, tmp_pcname);

        net_send(&fd, (unsigned char*)request, strlen(request));
        net_close(fd);

        fp = fopen("log.txt", "a");
        if(fp)
        {
            fprintf(fp, "[+] PCName=[%s] Path=[%s] PID=[%d]\n", pcname, procpath, pid);
            fclose(fp);
        }
        else
            printf("[-] ERROR Cannot open the log file!\n");

        delete request;
    }

}

void PrintProcessNameAndID( DWORD processID )
{
    //char szProcessName[MAX_PATH] = "<unknown>";
    char szProcessPath[MAX_PATH] = "<unknown>";
    char pcname[150];
    DWORD pcname_size = 150;
    // Get a handle to the process.

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, processID );

    // Get the process name.

    if (NULL != hProcess )
    {
        HMODULE hMod;
        DWORD cbNeeded;


        //if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
        {
            //SetLastError(0);
            GetProcessImageFileName( hProcess, szProcessPath, MAX_PATH);

            //GetModuleBaseName( hProcess, NULL, szProcessName, MAX_PATH);

        }

        GetComputerName(pcname, &pcname_size);
        signal_cec(szProcessPath, processID, pcname);
    }

    // Print the process name and identifier.

    _tprintf( TEXT("[+] FOUND! PID: [%u] Path: [%s]\n"), processID, szProcessPath );

    // Release the handle to the process.

    CloseHandle( hProcess );
}

bool CompareByteArray( BYTE Address[], BYTE ByteArray[], UINT Length )
{
    if(Address[0] != ByteArray[0])
    {
        return false;
    }

    for(UINT Index = 0; Index < Length; Index++)
    {
        if(Address[Index] != ByteArray[Index])
        {
            if(ByteArray[Index] != 0xEE)
            {
                return false;
            }
        }
    }
    return true;
}

DWORD RemoteSignatureLocator(HANDLE hProcess, DWORD dwStart, DWORD codeLength, BYTE pattern[], UINT Length)
{
    BYTE *tmp = new BYTE[1024*16];
    BYTE *sig = new BYTE[Length+1];

    BYTE *all = (BYTE*)VirtualAlloc(NULL, codeLength+1024*16, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE); //new BYTE[codeLength+1024*16];



    for(DWORD i=0; i<codeLength; i+=(1024*16))
    {
        DWORD dwRead = 0, oldProtect=0;
        //int vp=VirtualProtectEx(hProcess, (void*)(dwStart+i), 1024*1, PAGE_EXECUTE_READWRITE, &oldProtect);
        int ret = ReadProcessMemory(hProcess,(void*)(dwStart+i), tmp, 1024*16, &dwRead);
        memcpy(&all[i], tmp, dwRead);
    }

    for(DWORD k=0; k<(codeLength-Length); k++)
    {
        if(memcmp(&all[k], pattern, Length)==0){
            delete sig;
            delete tmp;

            VirtualFree(all, 0, MEM_RELEASE);
            return 1;
        }
    }
    delete sig;
    delete tmp;
    VirtualFree(all, 0, MEM_RELEASE);

    return 0;
}

char *rot13(char *s)
{
        char *p=s;
        int upper;

        while(*p) {
                upper=toupper(*p);
                if(upper>='A' && upper<='M') *p+=13;
                else if(upper>='N' && upper<='Z') *p-=13;
                ++p;
        }
        return s;
}

void tolower(char *str)
{
    int s=strlen(str);
    for(int i=0; i<s; i++)
        str[i] = tolower(str[i]);

}

int main( void )
{

    char pattern[]="R0VUIC8xMjM0NTY3ODk=";

    HANDLE currentProcessToken;
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;


    printf( " Meterpreter Payload Detector V.0.3RC2     \n"
            "    host                  \n\n\n");

    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &currentProcessToken);

    printf("[i] Debug privileges: [%d]\n", SetPrivilege(currentProcessToken,TEXT("SeDebugPrivilege") ,true));
    while(1)
    {
        printf("[i] Cycle started\n");
        if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
        {
            return 1;
        }

        cProcesses = cbNeeded / sizeof(DWORD);

        for ( i = 0; i < cProcesses; i++ )
        {
            if( aProcesses[i] != 0 && aProcesses[i] != GetCurrentProcessId())
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS , FALSE, aProcesses[i]);
                if(hProcess)
                {
                    PROCESS_MEMORY_COUNTERS pmc;

                    printf("[i] Analyzing PID: %d\n", aProcesses[i]);
                    //BYTE pattern[] = {0x7C, 0x44, 0x8B, 0x84};
                    //BYTE pattern[] = {0x7C, 0x44, 0x8B, 0x84, 0x24, 0xEC, 0x00, 0x00, 0x00, 0x83, 0xF8, 0x01, 0x75, 0x17, 0x8B, 0x55};
                    //BYTE pattern[] = {0x53, 0xE8, 0xF1, 0xC8, 0xFD, 0xFF, 0x8B};
                    //BYTE pattern[] = {0x83, 0xC4, 0x04, 0x83, 0xCA};

                    //3b3f0
                    //BYTE pattern[] = {0x74, 0x10, 0x53, 0x56, 0xE8, 0x47, 0xE2, 0xFD, 0xFF, 0x56, 0xE8, 0x91, 0x35, 0xFD, 0xFF, 0x83};
                    //[+] Injected the
                    //char pattern[]="GET /123456789";

                    char dec_pattern[200] = {0};
                    size_t dec_pattern_size = 200;
                    base64_decode((unsigned char*)dec_pattern, &dec_pattern_size, (unsigned char*)pattern, strlen(pattern));
                    dec_pattern[dec_pattern_size] = 0;
                    //strcat(&dec_pattern[200], "crashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtestcrashtest");


                    GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

                    if(RemoteSignatureLocator(hProcess, 1024*64, pmc.WorkingSetSize+1024*1024*250, (BYTE*)dec_pattern, strlen(dec_pattern)))
                    {

                        char szProcessPath[MAX_PATH];
                        GetProcessImageFileName( hProcess, szProcessPath, MAX_PATH);
                        tolower(szProcessPath);

                        /*if(!strstr(szProcessPath, "windows\\system32\\svchost.exe")){
                            PrintProcessNameAndID( aProcesses[i] );
                        }
                        else */if(!RemoteSignatureLocator(hProcess, 1024*64, pmc.WorkingSetSize+1024*1024*250, (BYTE*)"host", strlen("host")))
                        {
                            PrintProcessNameAndID( aProcesses[i] );
                        }
                        else
                        {
                            printf("[i] [%s] is safe, not reported\n", szProcessPath);
                        }

                    }
                    CloseHandle(hProcess);
                }
                else
                {
                    //printf("FAILED TO OPEN THIS PID %d\n", aProcesses[i]);
                }

            }
        }
        printf("[i] Waiting 5 minutes before restart\n");
        Sleep(60*1000*5);
    }
    return 0;
}
