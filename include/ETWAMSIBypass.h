#ifndef ETW_AMSI_BYPASS_H
#define ETW_AMSI_BYPASS_H

#include <windows.h>

class TelemetryBypass {
private:
    static BOOL PatchFunction(const char* dllName, const char* functionName, BYTE* patch, SIZE_T patchSize);
    static BOOL PatchETWFunction(const char* functionName);

public:
    static BOOL DisableETW();
    static BOOL DisableAMSI();
    static BOOL DisableTelemetry();
};

#endif // ETW_AMSI_BYPASS_H
