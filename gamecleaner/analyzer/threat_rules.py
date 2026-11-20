"""
Threat detection rules, API signatures, and heuristic definitions.
"""
from enum import Enum
import re
from typing import Dict, List, Set


class ThreatSeverity(Enum):
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(Enum):
    BENIGN = "Benign / Normal Game Component"
    HACKTOOL_CRACK = "HackTool / DRM Emulator (Benign Crack Hook)"
    PACKED_OBFUSCATED = "Packed / High Entropy Obfuscation"
    INFOSTEALER = "Credential & Browser Stealer"
    INJECTION = "Process Injection / Memory Hollowing"
    KEYLOGGER_SPYWARE = "Keylogger / Surveillance"
    COINMINER = "Cryptocurrency Miner"
    NETWORK_C2 = "Hidden Network Downloader / C2 Beacon"
    PERSISTENCE = "System Persistence / Autorun"


# Sensitive Windows APIs categorized by potential malicious capability
SENSITIVE_APIS: Dict[str, Dict[str, str]] = {
    # Infostealer indicators (99% of stealers like Lumma, Redline, Vidar decrypt browser credentials)
    "CryptUnprotectData": {
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
        "description": "Decrypts protected local credentials (used to steal Chrome/Edge/Firefox cookies & passwords)",
    },
    "CredEnumerateA": {
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Enumerates saved Windows credentials and passwords",
    },
    "CredEnumerateW": {
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Enumerates saved Windows credentials and passwords",
    },
    "VaultOpenVault": {
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Accesses Windows Vault stored passwords",
    },
    "VaultGetItem": {
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Retrieves credentials from Windows Vault",
    },

    # Virtual Memory & Hooking (Inline DRM hooks vs Injection)
    "VirtualProtect": {
        "category": ThreatCategory.HACKTOOL_CRACK.value,
        "severity": ThreatSeverity.LOW.value,
        "description": "Changes virtual memory page protection (standard for inline DRM hooks and unpackers)",
    },
    "VirtualProtectEx": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Changes virtual memory page protection inside an external target process",
    },

    # Process Injection / Memory Hollowing (Used by stealth droppers)
    "WriteProcessMemory": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Writes data directly to another process's virtual memory space",
    },
    "VirtualAllocEx": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Allocates memory inside an external target process",
    },
    "CreateRemoteThread": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Executes a thread in the address space of another process",
    },
    "NtCreateThreadEx": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Native syscall thread execution in target process",
    },
    "RtlCreateUserThread": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Low-level user thread creation in remote process",
    },
    "NtUnmapViewOfSection": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Hollows out a legitimate process binary to replace it with payload",
    },
    "NtWriteVirtualMemory": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Native syscall writing directly into process memory",
    },
    "NtAllocateVirtualMemory": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Native syscall allocating virtual memory space",
    },
    "SetThreadContext": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Modifies execution context (registers/EIP/RIP) of another thread",
    },
    "GetThreadContext": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Reads thread CPU register context for injection / hollowing",
    },
    "ResumeThread": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.LOW.value,
        "description": "Resumes thread execution (common in hollowed process launches)",
    },
    "QueueUserAPC": {
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Asynchronous procedure call injection",
    },

    # Spyware / Keylogging
    "GetAsyncKeyState": {
        "category": ThreatCategory.KEYLOGGER_SPYWARE.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Checks keystrokes asynchronously (common in keyloggers, but also game input)",
    },
    "SetWindowsHookExA": {
        "category": ThreatCategory.KEYLOGGER_SPYWARE.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Installs global keyboard/mouse hooks to intercept system input",
    },
    "SetWindowsHookExW": {
        "category": ThreatCategory.KEYLOGGER_SPYWARE.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Installs global keyboard/mouse hooks to intercept system input",
    },
    "GetClipboardData": {
        "category": ThreatCategory.KEYLOGGER_SPYWARE.value,
        "severity": ThreatSeverity.LOW.value,
        "description": "Reads clipboard data (standard game UI text paste, or suspicious crypto clippers)",
    },

    # Hidden Network Downloader / C2 Exfiltration
    "URLDownloadToFileA": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Downloads external payload from internet to disk",
    },
    "URLDownloadToFileW": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Downloads external payload from internet to disk",
    },
    "InternetOpenA": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Initializes WinINet application HTTP/FTP connection",
    },
    "InternetOpenW": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Initializes WinINet application HTTP/FTP connection",
    },
    "InternetOpenUrlA": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Opens an HTTP resource directly",
    },
    "HttpSendRequestA": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Sends HTTP request (frequently used for C2 data exfiltration)",
    },
    "HttpSendRequestW": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Sends HTTP request (frequently used for C2 data exfiltration)",
    },
    "WinHttpOpen": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Initializes WinHttp network communication session",
    },
    "WinHttpConnect": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Connects WinHttp session to target host or C2 server",
    },
    "WinHttpOpenRequest": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Creates HTTP request handle for network payload transfer",
    },
    "WinHttpSendRequest": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.MEDIUM.value,
        "description": "Transmits HTTP request over WinHttp",
    },
    "WSAStartup": {
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.LOW.value,
        "description": "Initializes Windows Sockets network subsystem (standard for games/coop)",
    },

    # Persistence
    "RegSetValueExA": {
        "category": ThreatCategory.PERSISTENCE.value,
        "severity": ThreatSeverity.LOW.value,
        "description": "Writes to Windows Registry (often used for Run/Autorun keys)",
    },
    "CreateServiceA": {
        "category": ThreatCategory.PERSISTENCE.value,
        "severity": ThreatSeverity.HIGH.value,
        "description": "Creates a permanent Windows background service",
    },
}

# Suspicious Strings and Regex Patterns (in ASCII or UTF-16)
SUSPICIOUS_STRING_PATTERNS = [
    {
        "pattern": re.compile(rb"https?://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", re.IGNORECASE),
        "name": "Discord Webhook Exfiltration",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}", re.IGNORECASE),
        "name": "Telegram Bot Token Exfiltration",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    # Modern Infostealers (Lumma, Stealc, Vidar, Redline)
    {
        "pattern": re.compile(rb"lummac2|lumma(?:\s+stealer|_c2)|gate\.php\?act=|\.lumma\b", re.IGNORECASE),
        "name": "Lumma Stealer C2 Signature",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"stealc(?:\s+stealer|/api/|_gate)|stealc_[a-z0-9]+", re.IGNORECASE),
        "name": "Stealc Stealer Signature",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"vidar(?:\s+stealer|_api)|redline(?:\.client|stealer)|raccoon\s+stealer|agenttesla", re.IGNORECASE),
        "name": "Vidar / Redline Infostealer Signature",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"(?:information\.txt|passwords\.txt|autofill\.txt|wallets\.txt|cards\.txt)[^\r\n]{0,200}(?:tokens\.txt|cookies\.txt)", re.IGNORECASE),
        "name": "Infostealer Staging Artifacts",
        "category": ThreatCategory.INFOSTEALER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    # Cryptocurrency Miners & Stratum Protocol
    {
        "pattern": re.compile(rb"stratum(?:\+tcp|\+ssl|2\+tcp)?://", re.IGNORECASE),
        "name": "Mining Pool Stratum Protocol",
        "category": ThreatCategory.COINMINER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(
            rb"nicehash\.com|minexmr\.com|supportxmr\.com|nanopool\.org|unmineable\.com|f2pool\.com|hashvault\.pro|moneroocean\.stream",
            re.IGNORECASE,
        ),
        "name": "Mining Pool Domain Artifact",
        "category": ThreatCategory.COINMINER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(
            rb"xmrig(?:\.exe)?|cryptonight|\brandomx\b|kawpow|ethminer|nbminer|phoenixminer|t-rex\.exe|srbminer|gupax|--donate-level",
            re.IGNORECASE,
        ),
        "name": "Cryptocurrency Mining Engine Artifacts",
        "category": ThreatCategory.COINMINER.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"vssadmin(?:\.exe)?\s+delete\s+shadows", re.IGNORECASE),
        "name": "Shadow Copy Deletion (Ransomware Behavior)",
        "category": ThreatCategory.INJECTION.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"powershell(?:\.exe)?\s+-[eE](?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
        "name": "Encoded PowerShell Dropper Execution",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.CRITICAL.value,
    },
    {
        "pattern": re.compile(rb"certutil(?:\.exe)?\s+-(?:urlcache|decode)", re.IGNORECASE),
        "name": "Certutil Lolbin Payload Download",
        "category": ThreatCategory.NETWORK_C2.value,
        "severity": ThreatSeverity.HIGH.value,
    },
]

# Standard Steamworks API exports that confirm a DLL is playing the role of Steam API wrapper
STANDARD_STEAM_EXPORTS: Set[str] = {
    "SteamAPI_Init",
    "SteamAPI_Shutdown",
    "SteamAPI_RunCallbacks",
    "SteamAPI_RegisterCallback",
    "SteamAPI_UnregisterCallback",
    "SteamInternal_CreateInterface",
    "SteamAPI_GetHSteamUser",
    "SteamAPI_GetHSteamPipe",
    "SteamClient",
    "SteamUser",
    "SteamFriends",
    "SteamUtils",
    "SteamMatchmaking",
    "SteamUserStats",
    "SteamApps",
    "SteamNetworking",
}

# Standard Epic Online Services exports
STANDARD_EOS_EXPORTS: Set[str] = {
    "EOS_Initialize",
    "EOS_Shutdown",
    "EOS_Platform_Create",
    "EOS_Platform_Tick",
    "EOS_Platform_Release",
    "EOS_Platform_GetAuthInterface",
    "EOS_Platform_GetConnectInterface",
    "EOS_EResult_ToString",
}

# Standard Ubisoft Connect / Uplay exports
STANDARD_UBISOFT_EXPORTS: Set[str] = {
    "UPLAY_START",
    "UPLAY_QUIT",
    "UPLAY_GetLastError",
    "UPLAY_USER_GetAccountId",
    "UPLAY_USER_GetUsername",
    "UPLAY_SAVE_GetSaveList",
    "UPLAY_ACH_GetAchievements",
}

