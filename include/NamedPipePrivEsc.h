#ifndef NAMEDPIPE_PRIVESC_H
#define NAMEDPIPE_PRIVESC_H

#include <windows.h>
#include <string>

using namespace std;

class NamedPipePrivEsc
{
private:
    static wstring GenerateRandomPipeName();
    static HANDLE CreateElevatedPipe(const wstring &pipeName);
    static BOOL TriggerSystemConnection(const wstring &pipeName);

public:
    static BOOL EscalatePrivileges();
    static BOOL IsSystemUser();
};

#endif // NAMEDPIPE_PRIVESC_H
