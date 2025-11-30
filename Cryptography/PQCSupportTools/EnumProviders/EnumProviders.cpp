// EnumProviders.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

void EnumProviders()
{
    NTSTATUS status;
    ULONG cbBuffer = 0;
    PCRYPT_PROVIDERS pBuffer = NULL;

    /*
    Get the providers, letting the BCryptEnumRegisteredProviders
    function allocate the memory.
    */
    status = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);

    if (NT_SUCCESS(status))
    {
        if (pBuffer != NULL)
        {
            // Enumerate the providers.
            for (ULONG i = 0; i < pBuffer->cProviders; i++)
            {
                printf("%S\n", pBuffer->rgpszProviders[i]);
            }
        }
    }
    else
    {
        printf("BCryptEnumRegisteredProviders failed with error "
            "code 0x%08x\n", status);
    }

    if (NULL != pBuffer)
    {
        /*
        Free the memory allocated by the
        BCryptEnumRegisteredProviders function.
        */
        BCryptFreeBuffer(pBuffer);
    }
}

int main()
{
    EnumProviders();
}
