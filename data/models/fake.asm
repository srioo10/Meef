start:
    PUSH EBP
    MOV EBP, ESP
    SUB ESP, 0x100

network_ops:
    CALL InternetConnectA
    CALL HttpOpenRequestA
    CALL send
    TEST EAX, EAX
    JZ error_handler

file_ops:
    CALL CreateFileA
    CALL WriteFile
    CALL ReadFile
    CMP EAX, 0
    JNE continue

registry_ops:
    CALL RegOpenKeyExA
    CALL RegSetValueExA
    CALL RegCloseKey

memory_ops:
    CALL VirtualAlloc
    CALL WriteProcessMemory
    MOV ECX, EAX

injection:
    CALL CreateRemoteThread
    CALL NtCreateThreadEx
    JMP cleanup

crypto_ops:
    CALL CryptEncrypt
    CALL CryptDecrypt
    CALL CryptHashData

persistence:
    CALL CreateServiceA
    CALL RegCreateKeyA
    CALL ShellExecuteA

cleanup:
    CALL CloseHandle
    XOR EAX, EAX
    POP EBP
    RET

error_handler:
    PUSH 0
    CALL ExitProcess
    RET
