"""
templates.py

A small, bundled (offline, no network needed) library of Sysmon detection
rule templates mapped to MITRE ATT&CK techniques, in the spirit of
community template menus like Cyb3rWard0g/ThreatHunter-Playbook's Sysmon
Shell templates.

Each Template targets one Sysmon event tag and bundles one or more filter
rules that, together, implement a specific detection idea. They're meant as
a fast starting point ("include" rules to start watching for a technique) -
review and tune before deploying broadly, since some of these are prone to
false positives depending on environment.

This is an intentionally small, hand-curated set, not a mirror of any
specific repository.
"""

from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Template:
    template_id: str          # e.g. "T1055_LoadLibrary"
    name: str                 # display name
    mitre_id: str             # e.g. "T1055"
    mitre_name: str           # e.g. "Process Injection"
    category: str             # menu grouping, e.g. "Defense Evasion"
    tag: str                  # Sysmon XML tag this applies to
    onmatch: str              # "include" or "exclude"
    description: str
    # list of (field, condition, value, comment)
    rules: List[Tuple[str, str, str, str]] = field(default_factory=list)


BUILTIN_TEMPLATES: List[Template] = [
    Template(
        template_id="T1055_LoadLibrary",
        name="Remote Thread → LoadLibrary",
        mitre_id="T1055", mitre_name="Process Injection",
        category="Defense Evasion / Privilege Escalation",
        tag="CreateRemoteThread", onmatch="include",
        description=(
            "Flags CreateRemoteThread events whose start function is LoadLibrary — "
            "a classic DLL injection pattern (a process creates a thread in another "
            "process that calls LoadLibrary to load an attacker DLL)."
        ),
        rules=[("StartFunction", "contains", "LoadLibrary",
                 "Possible DLL injection via CreateRemoteThread+LoadLibrary")],
    ),
    Template(
        template_id="T1218.010_Regsvr32",
        name="Regsvr32 Remote/Scriptlet Execution",
        mitre_id="T1218.010", mitre_name="System Binary Proxy Execution: Regsvr32",
        category="Defense Evasion",
        tag="ProcessCreate", onmatch="include",
        description=(
            "Flags regsvr32.exe invocations that reference a URL (http/https) or use "
            "the /i: scriptlet-registration switch — the 'Squiblydoo' living-off-the-land "
            "technique for executing remote code while bypassing AppLocker."
        ),
        rules=[
            ("CommandLine", "contains", "regsvr32", "regsvr32 usage"),
            ("CommandLine", "contains any", "http,https", "regsvr32 loading from a URL"),
        ],
    ),
    Template(
        template_id="T1218.004_InstallUtil",
        name="InstallUtil LOLBin Execution",
        mitre_id="T1218.004", mitre_name="System Binary Proxy Execution: InstallUtil",
        category="Defense Evasion",
        tag="ProcessCreate", onmatch="include",
        description=(
            "Flags InstallUtil.exe executions — a signed .NET utility frequently abused "
            "to execute arbitrary code and bypass application allowlisting."
        ),
        rules=[("Image", "end with", "InstallUtil.exe", "InstallUtil LOLBin")],
    ),
    Template(
        template_id="T1127_MSBuild",
        name="MSBuild Executing Inline Tasks",
        mitre_id="T1127", mitre_name="Trusted Developer Utilities Proxy Execution",
        category="Defense Evasion",
        tag="ProcessCreate", onmatch="include",
        description=(
            "Flags MSBuild.exe launches — a signed Microsoft binary that can compile and "
            "execute inline C# tasks embedded in a project file, often used to bypass "
            "application allowlisting."
        ),
        rules=[("Image", "end with", "MSBuild.exe", "MSBuild trusted-utility proxy execution")],
    ),
    Template(
        template_id="T1003_Wdigest_Downgrade",
        name="WDigest UseLogonCredential Enabled",
        mitre_id="T1003.001", mitre_name="OS Credential Dumping: LSASS Memory",
        category="Credential Access",
        tag="RegistryEvent", onmatch="include",
        description=(
            "Flags changes to the WDigest UseLogonCredential registry value. Setting it "
            "to 1 forces Windows to keep plaintext credentials in LSASS memory, a common "
            "pre-step before dumping credentials with tools like Mimikatz."
        ),
        rules=[("TargetObject", "end with",
                 "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential",
                 "WDigest downgrade to enable plaintext credential caching")],
    ),
    Template(
        template_id="T1003_LSASS_Access",
        name="Suspicious LSASS Process Access",
        mitre_id="T1003.001", mitre_name="OS Credential Dumping: LSASS Memory",
        category="Credential Access",
        tag="ProcessAccess", onmatch="include",
        description=(
            "Flags any process opening a handle to lsass.exe — review GrantedAccess and "
            "the source image; this fires on legitimate AV/EDR too, so exclude your own "
            "security tooling after reviewing hits."
        ),
        rules=[("TargetImage", "end with", "lsass.exe", "Handle opened to LSASS - review for credential dumping")],
    ),
    Template(
        template_id="T1547.001_Run_Keys",
        name="Run Key / Startup Folder Persistence",
        mitre_id="T1547.001", mitre_name="Boot or Logon Autostart Execution: Registry Run Keys",
        category="Persistence",
        tag="RegistryEvent", onmatch="include",
        description=(
            "Flags writes to the classic Run/RunOnce autostart registry keys, a very "
            "common persistence mechanism."
        ),
        rules=[
            ("TargetObject", "contains", "\\CurrentVersion\\Run\\", "Run key persistence"),
            ("TargetObject", "contains", "\\CurrentVersion\\RunOnce\\", "RunOnce key persistence"),
        ],
    ),
    Template(
        template_id="T1047_WMIC_Remote",
        name="WMIC Remote Process Creation",
        mitre_id="T1047", mitre_name="Windows Management Instrumentation",
        category="Execution / Lateral Movement",
        tag="ProcessCreate", onmatch="include",
        description=(
            "Flags wmic.exe invoked with 'process call create' and a /node: remote target "
            "— a common WMI-based lateral movement pattern."
        ),
        rules=[
            ("CommandLine", "contains", "process call create", "WMIC remote process creation"),
            ("CommandLine", "contains", "/node:", "WMIC targeting a remote host"),
        ],
    ),
    Template(
        template_id="T1021.006_Remote_PowerShell",
        name="Remote PowerShell Session (WinRM)",
        mitre_id="T1021.006", mitre_name="Remote Services: Windows Remote Management",
        category="Lateral Movement",
        tag="ProcessCreate", onmatch="include",
        description=(
            "Flags powershell.exe launched by wsmprovhost.exe (the WinRM host process), "
            "indicating an incoming remote PowerShell session (Enter-PSSession / Invoke-Command)."
        ),
        rules=[("ParentImage", "end with", "wsmprovhost.exe", "PowerShell spawned by a remote WinRM session")],
    ),
    Template(
        template_id="T1197_BITS_Jobs",
        name="BITSAdmin Download/Execute",
        mitre_id="T1197", mitre_name="BITS Jobs",
        category="Defense Evasion / Persistence",
        tag="ProcessCreate", onmatch="include",
        description=(
            "Flags bitsadmin.exe used with /transfer, a common way to download payloads "
            "or exfiltrate data while evading process-based network monitoring."
        ),
        rules=[
            ("Image", "end with", "bitsadmin.exe", "BITSAdmin usage"),
            ("CommandLine", "contains", "/transfer", "BITSAdmin file transfer job"),
        ],
    ),
    Template(
        template_id="T1546.008_AppInit_DLLs",
        name="AppInit_DLLs Registry Modification",
        mitre_id="T1546.010", mitre_name="Event Triggered Execution: AppInit DLLs",
        category="Persistence / Privilege Escalation",
        tag="RegistryEvent", onmatch="include",
        description=(
            "Flags changes to the AppInit_DLLs registry value, which forces a DLL to be "
            "loaded into every process that loads user32.dll — a legacy but still-abused "
            "persistence/injection technique."
        ),
        rules=[("TargetObject", "end with", "Windows\\AppInit_DLLs", "AppInit_DLLs persistence/injection")],
    ),
    Template(
        template_id="T1055_Reflective_DLL_Load",
        name="Unsigned Image Load into LSASS/Winlogon",
        mitre_id="T1055", mitre_name="Process Injection",
        category="Defense Evasion",
        tag="ImageLoad", onmatch="include",
        description=(
            "Flags unsigned DLLs being loaded into sensitive processes. Requires the "
            "ImageLoad section to be enabled (it's performance-heavy) and works best "
            "combined with an Image filter for lsass.exe/winlogon.exe in the same block."
        ),
        rules=[("Signed", "is", "false", "Unsigned image load - review target process and loaded DLL")],
    ),
]


def categories() -> List[str]:
    seen = []
    for t in BUILTIN_TEMPLATES:
        if t.category not in seen:
            seen.append(t.category)
    return seen


def templates_in_category(category: str) -> List[Template]:
    return [t for t in BUILTIN_TEMPLATES if t.category == category]


def get_template(template_id: str) -> Template:
    for t in BUILTIN_TEMPLATES:
        if t.template_id == template_id:
            return t
    raise KeyError(template_id)
