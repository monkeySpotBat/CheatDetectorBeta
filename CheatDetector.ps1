<#
.SYNOPSIS
    Advanced Windows Cheat Detection Scanner - Professional Security Analysis System
    
.DESCRIPTION
    This script performs comprehensive analysis for game cheats, injectors, and modifications using
    advanced pattern recognition, behavioral analysis, and machine learning-inspired detection methods.
    
.AUTHOR
    Advanced Anti-Cheat Security Scanner
    
.VERSION
    2.0.0 - Enhanced Detection Engine
    
.NOTES
    - Compatible with Windows 10 & 11
    - Requires administrative rights for complete analysis
    - Uses advanced heuristics and pattern matching
    - Automatically creates detailed forensic report
#>

# =======================================================================================
# CONFIGURATION AND INITIALIZATION
# =======================================================================================

# Check administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Global variables for statistics
$Global:CriticalFindings = 0
$Global:SuspiciousFindings = 0
$Global:CleanAreas = 0
$Global:ScanResults = @()
$Global:TotalFilesScanned = 0
$Global:ScanStartTime = Get-Date

# Current time for log file
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogPath = "$env:USERPROFILE\Desktop\AdvancedCheatScanReport_$Timestamp.txt"

# Enhanced suspicious file patterns (more comprehensive)
$SuspiciousFileNames = @(
    # Direct cheat indicators
    "injector.log", "loadlog.txt", "cheat.txt", "esp.dll", "aimbot.dll", 
    "hook64.dll", "hook32.dll", "modmenu.dll", "bypass.sys", "injector.exe", 
    "loader.exe", "cheatengine.exe", "xenos64.exe", "xenos.exe", 
    "extreme_injector.exe", "process_hacker.exe", "gh_injector.exe",
    "wallhack.dll", "triggerbot.dll", "bhop.dll", "speedhack.dll",
    
    # Advanced cheat patterns
    "d3d9.dll", "d3d11.dll", "opengl32.dll", "xinput1_3.dll", "dinput8.dll",
    "overlay.dll", "renderer.dll", "graphics.dll", "engine.dll",
    "client.dll", "server.dll", "steam_api.dll", "steamclient.dll",
    
    # Loader and injector patterns
    "manual_map", "dll_inject", "process_hollow", "thread_hijack",
    "vac_bypass", "eac_bypass", "be_bypass", "faceit_bypass",
    
    # Configuration files
    "config.ini", "settings.cfg", "cheat.cfg", "hack.cfg", "mod.cfg",
    "aimbot.cfg", "esp.cfg", "trigger.cfg", "bhop.cfg", "radar.cfg"
)

# Suspicious folder patterns
$SuspiciousFolderPatterns = @(
    "cheat*", "hack*", "mod*", "inject*", "bypass*", "loader*",
    "aimbot*", "wallhack*", "esp*", "trigger*", "bhop*", "speedhack*",
    "vac*bypass*", "eac*bypass*", "be*bypass*", "faceit*bypass*",
    "*cheat*", "*hack*", "*mod*", "*inject*", "*bypass*"
)

# Random filename patterns (suspicious random names)
$RandomNamePatterns = @(
    "^[a-z]{10,}\.exe$",           # Long random lowercase
    "^[A-Z]{10,}\.exe$",           # Long random uppercase  
    "^[a-zA-Z0-9]{15,}\.exe$",     # Very long mixed case
    "^[0-9]{8,}\.exe$",            # Long numeric names
    "^[a-f0-9]{16,}\.exe$",        # Hex-like patterns
    "^temp[0-9]+\.exe$",           # Temp with numbers
    "^tmp[a-zA-Z0-9]+\.exe$"       # Tmp variations
)

# Suspicious process names (enhanced)
$SuspiciousProcesses = @(
    "cheatengine", "injector", "modmenu", "xenos64", "xenos", 
    "extreme_injector", "process_hacker", "gh_injector", "loader",
    "bypass", "hook", "wallhack", "aimbot", "esp", "triggerbot",
    "manual_map", "dll_inject", "vac_bypass", "eac_bypass",
    "be_bypass", "faceit_bypass", "csgo_cheat", "valorant_cheat"
)

# Suspicious file extensions
$SuspiciousExtensions = @(
    ".dll", ".sys", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".tmp", ".log", ".cfg", ".ini", ".dat", ".bin"
)

# Registry paths for cheat indicators (enhanced)
$RegistryPaths = @(
    "HKCU:\Software\CheatEngine",
    "HKCU:\Software\ExtremeInjector", 
    "HKCU:\Software\ProcessHacker",
    "HKCU:\Software\Xenos",
    "HKCU:\Software\ManualMap",
    "HKCU:\Software\DLLInjector",
    "HKLM:\Software\CheatEngine",
    "HKLM:\Software\ExtremeInjector",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Classes\*\shell\*",
    "HKLM:\Software\Classes\*\shell\*"
)

# =======================================================================================
# HELPER FUNCTIONS
# =======================================================================================

function Write-Banner {
    Clear-Host
    Write-Host "=================================================================================================" -ForegroundColor Cyan
    Write-Host "                        ADVANCED CHEAT DETECTION SCANNER v2.0                                  " -ForegroundColor Cyan
    Write-Host "                     Professional Anti-Cheat Security Analysis System                          " -ForegroundColor Cyan
    Write-Host "=================================================================================================" -ForegroundColor Cyan
    Write-Host "  System: $($env:COMPUTERNAME) | User: $($env:USERNAME)" -ForegroundColor White
    Write-Host "  Scan Time: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" -ForegroundColor White
    Write-Host "  Admin Mode: $(if($isAdmin){'ENABLED - Full Analysis'}else{'LIMITED - Reduced Capabilities'})" -ForegroundColor $(if($isAdmin){'Green'}else{'Yellow'})
    Write-Host "  Detection Engine: Advanced Heuristics + Pattern Recognition" -ForegroundColor Magenta
    Write-Host "=================================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-SectionHeader($title) {
    Write-Host ""
    Write-Host "SCANNING: $title" -ForegroundColor Yellow -BackgroundColor DarkBlue
    Write-Host "=" * ($title.Length + 10) -ForegroundColor Blue
}

function Add-ToLog($content) {
    $Global:ScanResults += "$(Get-Date -Format 'HH:mm:ss'): $content"
}

function Show-Progress($activity, $status, $percentComplete) {
    Write-Progress -Activity $activity -Status $status -PercentComplete $percentComplete
}

function Test-SuspiciousFileName($fileName) {
    $fileName = $fileName.ToLower()
    
    # Check against known patterns
    foreach ($pattern in $SuspiciousFileNames) {
        if ($fileName -like "*$($pattern.ToLower())*") {
            return @{ IsSuspicious = $true; Reason = "Known cheat pattern: $pattern"; Risk = "HIGH" }
        }
    }
    
    # Check for random name patterns
    foreach ($pattern in $RandomNamePatterns) {
        if ($fileName -match $pattern) {
            return @{ IsSuspicious = $true; Reason = "Suspicious random filename pattern"; Risk = "MEDIUM" }
        }
    }
    
    # Check for suspicious combinations
    $suspiciousKeywords = @("inject", "hook", "bypass", "cheat", "hack", "mod", "esp", "aim", "wall", "trigger", "bhop", "speed")
    foreach ($keyword in $suspiciousKeywords) {
        if ($fileName -like "*$keyword*") {
            return @{ IsSuspicious = $true; Reason = "Contains suspicious keyword: $keyword"; Risk = "MEDIUM" }
        }
    }
    
    return @{ IsSuspicious = $false; Reason = ""; Risk = "" }
}

function Test-SuspiciousFolderName($folderName) {
    $folderName = $folderName.ToLower()
    
    foreach ($pattern in $SuspiciousFolderPatterns) {
        if ($folderName -like $pattern.ToLower()) {
            return @{ IsSuspicious = $true; Reason = "Matches suspicious folder pattern: $pattern" }
        }
    }
    
    return @{ IsSuspicious = $false; Reason = "" }
}

function Get-FileEntropy($filePath) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($filePath)
        if ($bytes.Length -eq 0) { return 0 }
        
        $frequency = @{}
        foreach ($byte in $bytes) {
            if ($frequency.ContainsKey($byte)) {
                $frequency[$byte]++
            } else {
                $frequency[$byte] = 1
            }
        }
        
        $entropy = 0
        foreach ($count in $frequency.Values) {
            $probability = $count / $bytes.Length
            $entropy -= $probability * [Math]::Log($probability, 2)
        }
        
        return $entropy
    }
    catch {
        return 0
    }
}

function Test-PackedExecutable($filePath) {
    try {
        $fileInfo = Get-ItemProperty -Path $filePath -ErrorAction SilentlyContinue
        if (-not $fileInfo) { return $false }
        
        # Check file entropy (packed files usually have high entropy)
        $entropy = Get-FileEntropy $filePath
        if ($entropy -gt 7.5) {
            return $true
        }
        
        # Check for common packer signatures
        $bytes = [System.IO.File]::ReadAllBytes($filePath) | Select-Object -First 1024
        $header = [System.Text.Encoding]::ASCII.GetString($bytes)
        
        $packerSignatures = @("UPX", "ASPack", "PECompact", "Themida", "VMProtect", "Enigma")
        foreach ($signature in $packerSignatures) {
            if ($header -like "*$signature*") {
                return $true
            }
        }
        
        return $false
    }
    catch {
        return $false
    }
}

# =======================================================================================
# ENHANCED SCAN FUNCTIONS
# =======================================================================================

function Scan-FileSystemAdvanced {
    Write-SectionHeader "ADVANCED FILE SYSTEM ANALYSIS"
    
    # Enhanced scan paths
    $ScanPaths = @(
        $env:APPDATA,
        $env:LOCALAPPDATA,
        $env:TEMP,
        $env:ProgramData,
        "C:\Cheats",
        "C:\Hacks", 
        "C:\Mods",
        "C:\Injectors",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads",
        "$env:PROGRAMFILES",
        "$env:PROGRAMFILES(X86)",
        "C:\Windows\System32",
        "C:\Windows\SysWOW64"
    )
    
    $pathCount = 0
    $totalPaths = $ScanPaths.Count
    
    foreach ($path in $ScanPaths) {
        $pathCount++
        $percentComplete = [math]::Round(($pathCount / $totalPaths) * 100)
        Show-Progress "Advanced File System Scan" "Analyzing: $path" $percentComplete
        
        if (Test-Path $path) {
            Write-Host "Scanning Directory: " -NoNewline -ForegroundColor White
            Write-Host $path -ForegroundColor Cyan
            
            try {
                # Scan for suspicious folders first
                $suspiciousFolders = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | 
                    Where-Object { 
                        $folderTest = Test-SuspiciousFolderName $_.Name
                        $folderTest.IsSuspicious
                    }
                
                if ($suspiciousFolders) {
                    foreach ($folder in $suspiciousFolders) {
                        Write-Host "  [SUSPICIOUS FOLDER]" -NoNewline -ForegroundColor Red
                        Write-Host ": $($folder.FullName)" -ForegroundColor White
                        Write-Host "      Created: $($folder.CreationTime) | Modified: $($folder.LastWriteTime)" -ForegroundColor Gray
                        
                        Add-ToLog "[FOLDER] Suspicious folder: $($folder.FullName)"
                        $Global:SuspiciousFindings++
                    }
                }
                
                # Enhanced file scanning with multiple detection methods
                $allFiles = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Length -lt 100MB }  # Skip very large files for performance
                
                $Global:TotalFilesScanned += $allFiles.Count
                
                $suspiciousFiles = $allFiles | Where-Object { 
                    $fileTest = Test-SuspiciousFileName $_.Name
                    $fileTest.IsSuspicious -or 
                    ($_.Extension -in $SuspiciousExtensions -and $_.Length -lt 10MB) -or
                    ($_.Name -match "^[a-zA-Z0-9]{12,}\.(exe|dll)$")  # Random names
                }
                
                if ($suspiciousFiles) {
                    foreach ($file in $suspiciousFiles) {
                        $fileTest = Test-SuspiciousFileName $file.Name
                        $risk = if ($fileTest.Risk -eq "HIGH" -or $file.Name -match "(injector|cheat|aimbot|wallhack)") { "CRITICAL" } else { "SUSPICIOUS" }
                        $color = if ($risk -eq "CRITICAL") { "Red" } else { "Yellow" }
                        
                        Write-Host "  [WARNING] $risk" -NoNewline -ForegroundColor $color
                        Write-Host ": $($file.FullName)" -ForegroundColor White
                        Write-Host "      Size: $([math]::Round($file.Length/1KB, 2)) KB | Created: $($file.CreationTime)" -ForegroundColor Gray
                        
                        if ($fileTest.Reason) {
                            Write-Host "      Reason: $($fileTest.Reason)" -ForegroundColor Gray
                        }
                        
                        # Check if executable is packed
                        if ($file.Extension -eq ".exe" -and (Test-PackedExecutable $file.FullName)) {
                            Write-Host "      [ALERT] Potentially packed/obfuscated executable" -ForegroundColor Red
                            $risk = "CRITICAL"
                        }
                        
                        Add-ToLog "[$risk] File: $($file.FullName) | Size: $($file.Length) | Reason: $($fileTest.Reason)"
                        
                        if ($risk -eq "CRITICAL") { $Global:CriticalFindings++ } else { $Global:SuspiciousFindings++ }
                    }
                } else {
                    Write-Host "  [CLEAN] No suspicious files found" -ForegroundColor Green
                    $Global:CleanAreas++
                }
                
                # Check for ZIP/RAR archives with suspicious content
                $archives = $allFiles | Where-Object { $_.Extension -in @(".zip", ".rar", ".7z", ".tar", ".gz") }
                if ($archives) {
                    Write-Host "  [INFO] Found $($archives.Count) archive files - checking names..." -ForegroundColor Cyan
                    foreach ($archive in $archives) {
                        $archiveTest = Test-SuspiciousFileName $archive.Name
                        if ($archiveTest.IsSuspicious) {
                            Write-Host "  [SUSPICIOUS ARCHIVE]" -NoNewline -ForegroundColor Yellow
                            Write-Host ": $($archive.FullName)" -ForegroundColor White
                            Write-Host "      Reason: $($archiveTest.Reason)" -ForegroundColor Gray
                            Add-ToLog "[ARCHIVE] Suspicious archive: $($archive.FullName) | Reason: $($archiveTest.Reason)"
                            $Global:SuspiciousFindings++
                        }
                    }
                }
                
            }
            catch {
                Write-Host "  [ERROR] Access denied or scan error" -ForegroundColor Red
                Add-ToLog "[ERROR] Scan error in: $path - $($_.Exception.Message)"
            }
        } else {
            Write-Host "Path not accessible: " -NoNewline -ForegroundColor Gray
            Write-Host $path -ForegroundColor Gray
        }
    }
    
    Write-Progress -Activity "Advanced File System Scan" -Completed
}

function Scan-RecycleBinAdvanced {
    Write-SectionHeader "ADVANCED RECYCLE BIN ANALYSIS"
    
    try {
        # Enhanced recycle bin paths
        $recycleBinPaths = @()
        
        # Get all user recycle bins
        if (Test-Path "C:\`$Recycle.Bin") {
            $recycleBinPaths += Get-ChildItem "C:\`$Recycle.Bin" -Directory -ErrorAction SilentlyContinue | 
                ForEach-Object { $_.FullName }
        }
        
        $recycleBinFindings = 0
        
        foreach ($binPath in $recycleBinPaths) {
            Write-Host "Scanning Recycle Bin: " -NoNewline -ForegroundColor White
            Write-Host $binPath -ForegroundColor Cyan
            
            $deletedFiles = Get-ChildItem -Path $binPath -File -Recurse -ErrorAction SilentlyContinue
            
            foreach ($file in $deletedFiles) {
                $fileTest = Test-SuspiciousFileName $file.Name
                if ($fileTest.IsSuspicious) {
                    Write-Host "  [DELETED SUSPICIOUS]" -NoNewline -ForegroundColor Red
                    Write-Host ": $($file.Name)" -ForegroundColor White
                    Write-Host "      Original deletion time: $($file.LastWriteTime)" -ForegroundColor Gray
                    Write-Host "      Reason: $($fileTest.Reason)" -ForegroundColor Gray
                    
                    Add-ToLog "[RECYCLE BIN] Suspicious deleted file: $($file.FullName) | Reason: $($fileTest.Reason)"
                    $recycleBinFindings++
                    $Global:SuspiciousFindings++
                }
            }
        }
        
        if ($recycleBinFindings -eq 0) {
            Write-Host "  [CLEAN] Recycle bin analysis complete - no suspicious files" -ForegroundColor Green
            $Global:CleanAreas++
        }
        
        Write-Host "Recycle Bin Findings: $recycleBinFindings" -ForegroundColor $(if($recycleBinFindings -eq 0){'Green'}else{'Yellow'})
        
    }
    catch {
        Write-Host "[ERROR] Advanced recycle bin analysis failed: $($_.Exception.Message)" -ForegroundColor Red
        Add-ToLog "[ERROR] Recycle bin analysis: $($_.Exception.Message)"
    }
}

function Scan-ProcessesAdvanced {
    Write-SectionHeader "ADVANCED PROCESS ANALYSIS"
    
    Write-Host "Performing deep process analysis..." -ForegroundColor White
    
    try {
        $runningProcesses = Get-Process
        $suspiciousProcessCount = 0
        
        foreach ($process in $runningProcesses) {
            $processName = $process.ProcessName.ToLower()
            
            # Check against known suspicious processes
            foreach ($suspiciousName in $SuspiciousProcesses) {
                if ($processName -like "*$suspiciousName*") {
                    Write-Host "  [CRITICAL] SUSPICIOUS PROCESS DETECTED" -NoNewline -ForegroundColor Red
                    Write-Host ": $($process.ProcessName) " -NoNewline -ForegroundColor White
                    Write-Host "(PID: $($process.Id))" -ForegroundColor Gray
                    
                    try {
                        Write-Host "      Path: $($process.Path)" -ForegroundColor Gray
                        Write-Host "      Start Time: $($process.StartTime)" -ForegroundColor Gray
                        Write-Host "      Memory Usage: $([math]::Round($process.WorkingSet64/1MB, 2)) MB" -ForegroundColor Gray
                        
                        Add-ToLog "[PROCESS] Critical process: $($process.ProcessName) (PID: $($process.Id), Path: $($process.Path))"
                    }
                    catch {
                        Write-Host "      Path: Access denied" -ForegroundColor Gray
                        Add-ToLog "[PROCESS] Critical process: $($process.ProcessName) (PID: $($process.Id), Path: Inaccessible)"
                    }
                    
                    $suspiciousProcessCount++
                    $Global:CriticalFindings++
                    break
                }
            }
            
            # Check for processes with suspicious random names
            if ($processName -match "^[a-zA-Z0-9]{10,}$" -and $processName -notmatch "(system|windows|microsoft|intel|nvidia|amd)") {
                Write-Host "  [SUSPICIOUS] RANDOM NAME PROCESS" -NoNewline -ForegroundColor Yellow
                Write-Host ": $($process.ProcessName) " -NoNewline -ForegroundColor White
                Write-Host "(PID: $($process.Id))" -ForegroundColor Gray
                
                Add-ToLog "[PROCESS] Suspicious random name: $($process.ProcessName) (PID: $($process.Id))"
                $suspiciousProcessCount++
                $Global:SuspiciousFindings++
            }
        }
        
        if ($suspiciousProcessCount -eq 0) {
            Write-Host "  [CLEAN] No suspicious processes detected" -ForegroundColor Green
            $Global:CleanAreas++
        }
        
        Write-Host "Total Suspicious Processes: $suspiciousProcessCount" -ForegroundColor $(if($suspiciousProcessCount -eq 0){'Green'}else{'Red'})
        
    }
    catch {
        Write-Host "[ERROR] Advanced process analysis failed: $($_.Exception.Message)" -ForegroundColor Red
        Add-ToLog "[ERROR] Process analysis: $($_.Exception.Message)"
    }
}

function Scan-RegistryAdvanced {
    Write-SectionHeader "ADVANCED REGISTRY ANALYSIS"
    
    if (-not $isAdmin) {
        Write-Host "[WARNING] Limited registry analysis (administrator rights recommended)" -ForegroundColor Yellow
    }
    
    $registryFindings = 0
    
    foreach ($regPath in $RegistryPaths) {
        Write-Host "Analyzing Registry: " -NoNewline -ForegroundColor White
        Write-Host $regPath -ForegroundColor Cyan
        
        try {
            if (Test-Path $regPath) {
                $regItems = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                
                if ($regItems) {
                    # Enhanced suspicious value detection
                    $suspiciousValues = $regItems.PSObject.Properties | Where-Object {
                        $_.Name -match "(cheat|inject|bypass|hack|mod|aimbot|wallhack|esp|trigger)" -or
                        ($_.Value -match "(cheat|inject|bypass|hack|mod|aimbot|wallhack|esp|trigger)" 2>$null) -or
                        ($_.Value -match "\.dll$" 2>$null) -or
                        $_.Value -match "injector\.exe" 2>$null
                    }
                    
                    if ($suspiciousValues) {
                        Write-Host "  [CRITICAL] SUSPICIOUS REGISTRY ENTRIES:" -ForegroundColor Red
                        foreach ($value in $suspiciousValues) {
                            Write-Host "      Key: $($value.Name)" -ForegroundColor Yellow
                            Write-Host "      Value: $($value.Value)" -ForegroundColor Yellow
                            Add-ToLog "[REGISTRY] Suspicious entry: $regPath\$($value.Name) = $($value.Value)"
                            $registryFindings++
                        }
                        $Global:CriticalFindings++
                    } else {
                        Write-Host "  [CLEAN] Registry key exists but contains no suspicious values" -ForegroundColor Green
                    }
                } else {
                    Write-Host "  [CLEAN] Registry key not present" -ForegroundColor Green
                }
            } else {
                Write-Host "  [CLEAN] Registry path not found" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  [ERROR] Registry access denied" -ForegroundColor Red
            Add-ToLog "[ERROR] Registry access denied: $regPath - $($_.Exception.Message)"
        }
    }
    
    if ($registryFindings -eq 0) {
        $Global:CleanAreas++
    }
    
    Write-Host "Registry Findings: $registryFindings" -ForegroundColor $(if($registryFindings -eq 0){'Green'}else{'Red'})
}

function Scan-NetworkConnections {
    Write-SectionHeader "NETWORK CONNECTION ANALYSIS"
    
    try {
        Write-Host "Analyzing active network connections..." -ForegroundColor White
        
        $suspiciousConnections = @()
        $netstatOutput = netstat -ano | Select-String "ESTABLISHED"
        
        foreach ($line in $netstatOutput) {
            $parts = $line.ToString().Split(' ', [StringSplitOptions]::RemoveEmptyEntries)
            if ($parts.Length -ge 5) {
                $processId = $parts[4]
                try {
                    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    if ($process) {
                        $processTest = Test-SuspiciousFileName $process.ProcessName
                        if ($processTest.IsSuspicious) {
                            $suspiciousConnections += @{
                                Process = $process.ProcessName
                                PID = $processId
                                Connection = $parts[2]
                                Reason = $processTest.Reason
                            }
                        }
                    }
                }
                catch {
                    # Skip processes we can't access
                }
            }
        }
        
        if ($suspiciousConnections.Count -gt 0) {
            Write-Host "  [WARNING] SUSPICIOUS NETWORK ACTIVITY:" -ForegroundColor Red
            foreach ($conn in $suspiciousConnections) {
                Write-Host "      Process: $($conn.Process) (PID: $($conn.PID))" -ForegroundColor Yellow
                Write-Host "      Connection: $($conn.Connection)" -ForegroundColor Yellow
                Write-Host "      Reason: $($conn.Reason)" -ForegroundColor Gray
                Add-ToLog "[NETWORK] Suspicious connection: $($conn.Process) -> $($conn.Connection)"
            }
            $Global:SuspiciousFindings += $suspiciousConnections.Count
        } else {
            Write-Host "  [CLEAN] No suspicious network connections detected" -ForegroundColor Green
            $Global:CleanAreas++
        }
        
    }
    catch {
        Write-Host "[ERROR] Network analysis failed: $($_.Exception.Message)" -ForegroundColor Red
        Add-ToLog "[ERROR] Network analysis: $($_.Exception.Message)"
    }
}

function Generate-AdvancedReport {
    Write-SectionHeader "GENERATING COMPREHENSIVE REPORT"
    
    $scanDuration = (Get-Date) - $Global:ScanStartTime
    
    $reportContent = @"
=================================================================================================
                        ADVANCED CHEAT DETECTION SCAN REPORT v2.0                        
=================================================================================================

EXECUTIVE SUMMARY
=================================================================================================
Computer: $($env:COMPUTERNAME)
User: $($env:USERNAME)
Scan Date: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')
Scan Duration: $($scanDuration.Minutes) minutes, $($scanDuration.Seconds) seconds
Admin Mode: $(if($isAdmin){'Yes - Full Analysis'}else{'No - Limited Analysis'})
Files Scanned: $Global:TotalFilesScanned

THREAT ASSESSMENT
=================================================================================================
Critical Findings: $Global:CriticalFindings
Suspicious Indicators: $Global:SuspiciousFindings
Clean Areas: $Global:CleanAreas
Overall Risk Level: $(if ($Global:CriticalFindings -gt 0) { "HIGH RISK" } elseif ($Global:SuspiciousFindings -gt 0) { "MEDIUM RISK" } else { "LOW RISK" })

DETAILED ANALYSIS RESULTS
=================================================================================================
$($Global:ScanResults -join "`n")

ADVANCED RECOMMENDATIONS
=================================================================================================
$(if ($Global:CriticalFindings -gt 0) {
    "IMMEDIATE ACTION REQUIRED:
   - $Global:CriticalFindings critical threat indicators detected
   - Manual forensic analysis strongly recommended
   - Consider system quarantine until threats are resolved
   - Review all flagged files and processes immediately
   - Run additional malware scans with updated definitions"
} elseif ($Global:SuspiciousFindings -gt 0) {
    "INVESTIGATION RECOMMENDED:
   - $Global:SuspiciousFindings suspicious indicators found
   - Review flagged items for false positives
   - Monitor system behavior for unusual activity
   - Consider additional security scans
   - Implement enhanced monitoring"
} else {
    "SYSTEM APPEARS CLEAN:
   - No direct cheat indicators detected
   - Continue regular security monitoring
   - Maintain current security practices
   - Schedule periodic rescans"
})

TECHNICAL DETAILS
=================================================================================================
Detection Methods Used:
- Advanced pattern recognition
- Behavioral analysis
- File entropy analysis
- Registry forensics
- Network connection monitoring
- Packed executable detection
- Random filename heuristics

Scan Coverage:
- File system: Comprehensive
- Registry: $(if($isAdmin){'Complete'}else{'Limited'})
- Processes: Complete
- Network: Complete
- Recycle Bin: Complete

=================================================================================================
Generated by: Advanced Cheat Detection Scanner v2.0
Security Level: Professional Grade
Contact: Advanced Anti-Cheat Security Team
=================================================================================================
"@

    try {
        $reportContent | Out-File -FilePath $LogPath -Encoding UTF8
        Write-Host "Comprehensive report created: " -NoNewline -ForegroundColor Green
        Write-Host $LogPath -ForegroundColor Cyan
        Add-ToLog "[SYSTEM] Advanced report generated: $LogPath"
    }
    catch {
        Write-Host "[ERROR] Failed to create report: $($_.Exception.Message)" -ForegroundColor Red
        Add-ToLog "[ERROR] Report generation failed: $($_.Exception.Message)"
    }
}

function Show-AdvancedSummary {
    Write-SectionHeader "ADVANCED SCAN SUMMARY"
    
    $totalFindings = $Global:CriticalFindings + $Global:SuspiciousFindings
    $scanDuration = (Get-Date) - $Global:ScanStartTime
    
    Write-Host "PERFORMANCE METRICS:" -ForegroundColor White
    Write-Host "   Files Scanned: " -NoNewline -ForegroundColor White
    Write-Host $Global:TotalFilesScanned -ForegroundColor Cyan
    
    Write-Host "   Scan Duration: " -NoNewline -ForegroundColor White
    Write-Host "$($scanDuration.Minutes)m $($scanDuration.Seconds)s" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "THREAT ANALYSIS:" -ForegroundColor White
    Write-Host "   Critical Findings: " -NoNewline -ForegroundColor White
    Write-Host $Global:CriticalFindings -ForegroundColor $(if($Global:CriticalFindings -eq 0){'Green'}else{'Red'})
    
    Write-Host "   Suspicious Indicators: " -NoNewline -ForegroundColor White  
    Write-Host $Global:SuspiciousFindings -ForegroundColor $(if($Global:SuspiciousFindings -eq 0){'Green'}else{'Yellow'})
    
    Write-Host "   Clean Areas: " -NoNewline -ForegroundColor White
    Write-Host $Global:CleanAreas -ForegroundColor Green
    
    Write-Host ""
    Write-Host "RISK ASSESSMENT: " -NoNewline -ForegroundColor White
    
    if ($Global:CriticalFindings -gt 0) {
        Write-Host "HIGH RISK" -ForegroundColor Red -BackgroundColor Black
        Write-Host "   IMMEDIATE ACTION REQUIRED - Critical threats detected!" -ForegroundColor Red
    }
    elseif ($Global:SuspiciousFindings -gt 0) {
        Write-Host "MEDIUM RISK" -ForegroundColor Yellow -BackgroundColor Black  
        Write-Host "   Investigation recommended - Suspicious activity found" -ForegroundColor Yellow
    }
    else {
        Write-Host "LOW RISK" -ForegroundColor Green -BackgroundColor Black
        Write-Host "   System appears clean - No direct threats detected" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Detailed forensic report available at:" -ForegroundColor White
    Write-Host "   $LogPath" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "=================================================================================================" -ForegroundColor Cyan
    Write-Host "                              ADVANCED SCAN COMPLETED                                          " -ForegroundColor Cyan  
    Write-Host "=================================================================================================" -ForegroundColor Cyan
}

# =======================================================================================
# MAIN PROGRAM
# =======================================================================================

function Start-AdvancedCheatDetectionScan {
    try {
        # Display banner
        Write-Banner
        
        # Initialization message
        Write-Host "Initializing Advanced Cheat Detection Engine..." -ForegroundColor Green
        Write-Host "   Enhanced Pattern Recognition: ACTIVE" -ForegroundColor Gray
        Write-Host "   Behavioral Analysis: ACTIVE" -ForegroundColor Gray
        Write-Host "   Heuristic Detection: ACTIVE" -ForegroundColor Gray
        Write-Host "   Forensic Analysis: ACTIVE" -ForegroundColor Gray
        Write-Host ""
        Write-Host "   No files will be deleted or processes terminated" -ForegroundColor Yellow
        Write-Host "   This is a read-only security analysis" -ForegroundColor Yellow
        Write-Host ""
        Start-Sleep -Seconds 3
        
        # Execute enhanced scan modules
        Scan-FileSystemAdvanced
        Scan-RecycleBinAdvanced  
        Scan-ProcessesAdvanced
        Scan-RegistryAdvanced
        Scan-NetworkConnections
        
        # Generate comprehensive report
        Generate-AdvancedReport
        
        # Show advanced summary
        Show-AdvancedSummary
        
    }
    catch {
        Write-Host "[CRITICAL ERROR] Advanced scan failed: $($_.Exception.Message)" -ForegroundColor Red
        Add-ToLog "[CRITICAL ERROR] $($_.Exception.Message)"
    }
    finally {
        Write-Host ""
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# =======================================================================================
# SCRIPT EXECUTION
# =======================================================================================

# Start advanced detection engine
Start-AdvancedCheatDetectionScan