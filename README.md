### Description
Delivery of gaming cheats from a server through encrypted payload.
# Features

✅ Encrypted Payload Delivery 
- Downloads a cheat binary from your server.

✅ Chunked Downloads 
- Downloads payload in randomized segments with delays to avoid traffic pattern detection.

✅ Traffic Spoofing 
- Uses Chrome user-agent
- Standard HTTP headers (Accept-Encoding, CacheControl).

✅ Garbage Collection Triggers 
- Allocates/frees memory to disrupt memory analysis.

✅ Timestamp Spoofing 
- Randomizes file timestamps to appear older.

✅ Event Log Cleaning 
- Clears system/application/security logs to hide execution.

✅ Registry Keys 
- Adds to HKCU\Software\Microsoft\Windows\CurrentVersion\Run for auto-start.

✅ WMI Event Subscription 
- Triggers execution at specific times.

✅ COM Hijacking 
- Modifies registry keys to load via COM objects.

✅ Memory Cleaning 
- Securely erases decrypted payloads to prevent memory dumping.

✅ Encrypted Strings 
- Obfuscates API names and debug messages using XOR like ENC_STR macro.

✅ Random Delays 
- Sleep intervals between operations to for behavioral analysis.

✅ Hardware Checks 
- Requires 2+ CPU cores, 4GB+ RAM, and mouse movement to avoid sandboxes.

✅ Debugger Detection 
- Scans for the following windows debuggers:
 - OllyDbg
 - x64dbg
 - IDA
- Scans for the following DLLs:
 - sbiedll.dll
 - dbghelp.dll.

✅ Environment Checks 
- Detects sandboxes, debuggers, VMs, and analysis tools.

✅ Direct Syscall Execution 
- Bypasses API hooks by resolving and calling NtUnmapViewOfSection directly.

✅ Process Hollowing 
- Injects into legitimate processes like explorer.exe, notepad.exe, etc.

✅ Multi-Stage Decryption 
- Uses XOR, tick count addition, and bit rotation to decrypt the payload in memory.
