#pragma once
// Function prototypes
BOOLEAN NTAPI InitializeChangeNotify();
NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING, ULONG, PUNICODE_STRING);
BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, BOOLEAN);
