#################################################################
# rcWinFileScan - PowerShell Script for analyzing a programs directory security.

# Import required module for PE analysis
#Install-Module -Name PESecurity -Force -SkipPublisherCheck

param ([string]$dirPath)

#################################################################
# Function to get file hashes
function Get-FileHashes {
    param ([string]$filePath)
    $md5 = Get-FileHash -Path $filePath -Algorithm MD5
    $sha256 = Get-FileHash -Path $filePath -Algorithm SHA256
    return $md5.Hash, $sha256.Hash
}

#################################################################
# Function to get PE file info
function Get-PEInfo {
    param ([string]$filePath)

    $peInfo = Get-PESecurity -file $filePath
    $arch = if ($peInfo.Is64Bit) { "64BIT" } else { "32BIT" }
    $secFeatures = @()

    if ($peInfo.ASLR) { $secFeatures += "ASLR" }
    if ($peInfo.DEP) { $secFeatures += "DEP" }
    if ($peInfo.SEH) { $secFeatures += "SEH" }
    if ($peInfo.SafeSEH) { $secFeatures += "SafeSEH" }
    if ($peInfo.StrongNaming) { $secFeatures += "StrongNaming" }

    return $arch, ($secFeatures -join ', ')
}

#################################################################
# Function to check if file is used as a service
function Check-IfService {
    param ([string]$filePath)
    $services = Get-WmiObject win32_service |Select-Object -ExpandProperty PathName
    foreach ($service in $services) {
        if ($service -match [regex]::Escape($fileName)) {
            return $true
        }
    }
    return $services -contains $filePath    
}

#################################################################
# Check Service Permissions
function Get-ServicePermissions {
    param([string]$serviceName)
    $service = Get-WmiObject Win32_Service -Filter "Name='$serviceName'"
    $serviceSecurity = $service.GetSecurityDescriptor().Descriptor.DACL
    $permString = ""
    foreach ($perm in $serviceSecurity) {
        $permString += $perm.Trustee.Name + " " + $perm.AccessMask + "; "
    }
    return ($permString)
}

#################################################################
# MAIN - Enumerate files, directories, permissions, etc.
Get-ChildItem -Path $dirPath -Recurse | ForEach-Object {
    $filePath = $_.FullName
    $fileSize = $_.Length / 1MB

    # Output file name and size
    Write-Host "[* FILE NAME *] $filePath"
    Write-Host "[* FILE SIZE *] ${fileSize}MB"

    # Output file hashes
    $md5, $sha256 = Get-FileHashes -filePath $filePath
    Write-Host "[* MDSUM * ] $md5"
    Write-Host "[* SHA256 *] $sha256"

    # Output file permissions
    $permissions = (Get-Acl -Path $filePath).Access
    $insecure = $false
    $permString = ""

    foreach ($perm in $permissions) {
        if ($perm.IdentityReference -eq "Everyone" -and $perm.FileSystemRights -eq "FullControl") {
            $insecure = $true
        }
        $permString += $perm.IdentityReference.ToString() + " " + $perm.FileSystemRights.ToString() + "; "
    }

    if ($insecure) {
        Write-Host "[* FILE PERMISSIONS *] " 
        Write-Host "$permString" -ForegroundColor Red
        Write-host "ALERT: INSECURE PERMISSIONS FOUND!" -ForegroundColor Red
    } 

    else {
        Write-Host "[* FILE PERMISSIONS *] $permString "
    }

    # Check if file is PE file
    $ext = [System.IO.Path]::GetExtension($filePath)
    if ($ext -eq '.exe' -or $ext -eq '.dll') {
        Write-Host "[* IS PE *] yes"

        # Check if used as a service
        $fileName = [System.IO.Path]::GetFileName($filePath)
        $isService = Check-IfService -filePath $fileName
        if ($isService) {
            Write-Host "[* USED AS SERVICE *] yes"

            # Get and output service permissions
            $servicePerms = Get-ServicePermissions -serviceName $fileName
            Write-host "[* SERVICE PERMISSIONS *] $servicePerms"
        }
        else {
            Write-Host "[* USED AS SERVICE *] no"
        }
        

        # Get PE info
        $arch, $secFeatures = Get-PEInfo -filePath $filePath
        Write-Host "[* ARCHITECTURE *] $arch"
        Write-Host "[* SECURITY FEATURES * ] $secFeatures"
    } 

    else {
        Write-Host "[* IS PE *] no"
    }

    Write-Host " "

}