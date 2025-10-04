# -----------------------------------------------------------------------------
# UEFI PowerShell Module v2
# Author: Michael Niehaus
# Description:
#   A sample module to show how to interact with UEFI variables using
#   PowerShell.  Provided as-is with no support.  See https://oofhours.com
#   for related information.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# One-time initialization
# -----------------------------------------------------------------------------

$definition = @'
 using System;
 using System.Runtime.InteropServices;
 using System.Text;
  
 public class UEFINative
 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 GetFirmwareEnvironmentVariableA(string lpName, string lpGuid, [Out] Byte[] lpBuffer, UInt32 nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 SetFirmwareEnvironmentVariableA(string lpName, string lpGuid, Byte[] lpBuffer, UInt32 nSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtEnumerateSystemEnvironmentValuesEx(UInt32 function, [Out] Byte[] lpBuffer, ref UInt32 nSize);
 }
'@

$uefiNative = Add-Type $definition -PassThru

# Global constants
$global:UEFIGlobal = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
$global:UEFIWindows = "{77FA9ABD-0359-4D32-BD60-28F4E78F784B}"
$global:UEFISurface = "{D2E0B9C9-9860-42CF-B360-F906D5E0077A}"
$global:UEFITesting = "{1801FBE3-AEF7-42A8-B1CD-FC4AFAE14716}"
$global:UEFISecurityDatabase = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}"


# -----------------------------------------------------------------------------
# Get-UEFIVariable
# -----------------------------------------------------------------------------

function Get-UEFIVariable
{
<#
.SYNOPSIS
    Gets the value of the specified UEFI firmware variable.

.DESCRIPTION
    Gets the value of the specified UEFI firmware variable.  This must be executed in an elevated process (requires admin rights).

.PARAMETER All
    Get the namespace and variable names for all available UEFI variables.

.PARAMETER Namespace
    A GUID string that specifies the specific UEFI namespace for the specified variable.  Some predefined namespace global variables
    are defined in this module.  If not specified, the UEFI global namespace ($UEFIGlobal) will be used.

.PARAMETER VariableName
    The name of the variable to be retrieved.  This parameter is mandatory.  An error will be returned if the variable does not exist.

.PARAMETER AsByteArray
    Switch to specify that the value of the specified UEFI variable should be returned as a byte array instead of as a string.

.EXAMPLE
    Get-UEFIVariable -All

.EXAMPLE
    Get-UEFIVariable -VariableName PlatformLang

.EXAMPLE
    Get-UEFIVariable -VariableName BootOrder -AsByteArray

.EXAMPLE
    Get-UEFIVariable -VariableName Blah -Namespace $UEFITesting

.OUTPUTS
    A string or byte array containing the current value of the specified UEFI variable.

.LINK
    https://oofhours.com/2019/09/02/geeking-out-with-uefi/

    
    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariablea

#Requires -Version 2.0
#>

    [cmdletbinding()]  
    Param(
        [Parameter(ParameterSetName='All', Mandatory = $true)]
        [Switch]$All,

        [Parameter(ParameterSetName='Single', Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [String]$Namespace = $global:UEFIGlobal,

        [Parameter(ParameterSetName='Single', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [String]$VariableName,

        [Parameter(ParameterSetName='Single', Mandatory=$false)]
        [Switch]$AsByteArray = $false
    )

    BEGIN {
        $rc = Set-LHSTokenPrivilege -Privilege SeSystemEnvironmentPrivilege
    }
    PROCESS {
        if ($All) {
            # Get the full variable list
            $VARIABLE_INFORMATION_NAMES = 1
            $size = 1024 * 1024
            $result = New-Object Byte[]($size)
            $rc = $uefiNative[0]::NtEnumerateSystemEnvironmentValuesEx($VARIABLE_INFORMATION_NAMES, $result, [ref] $size)
            $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($rc -eq 0)
            {
                $currentPos = 0
                while ($true)
                {
                    # Get the offset to the next entry
                    $nextOffset = [System.BitConverter]::ToUInt32($result, $currentPos)
                    if ($nextOffset -eq 0)
                    {
                        break
                    }
    
                    # Get the vendor GUID for the current entry
                    $guidBytes = $result[($currentPos + 4)..($currentPos + 4 + 15)]
                    [Guid] $vendor = [Byte[]]$guidBytes
                    
                    # Get the name of the current entry
                    $name = [System.Text.Encoding]::Unicode.GetString($result[($currentPos + 20)..($currentPos + $nextOffset - 1)])
    
                    # Return a new object to the pipeline
                    New-Object PSObject -Property @{Namespace = $vendor.ToString('B'); VariableName = $name.Replace("`0","") }
    
                    # Advance to the next entry
                    $currentPos = $currentPos + $nextOffset
                }
            }
            else
            {
                Write-Error "Unable to retrieve list of UEFI variables, last error = $lastError."
            }
        }
        else {
            # Get a single variable value
            $size = 1024
            $result = New-Object Byte[]($size)
            $rc = $uefiNative[0]::GetFirmwareEnvironmentVariableA($VariableName, $Namespace, $result, $size)
            $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($lastError -eq 122)
            {
                # Data area passed wasn't big enough, try larger.  Doing 32K all the time is slow, so this speeds it up.
                $size = 32*1024
                $result = New-Object Byte[]($size)
                $rc = $uefiNative[0]::GetFirmwareEnvironmentVariableA($VariableName, $Namespace, $result, $size)
                $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()    
            }
            if ($rc -eq 0)
            {
                Write-Error "Unable to retrieve variable $VariableName from namespace $Namespace, last error = $lastError."
                return ""
            }
            else
            {
                Write-Verbose "Variable $VariableName retrieved with $rc bytes"
                [System.Array]::Resize([ref] $result, $rc)
                if ($AsByteArray)
                {
                    return $result
                }
                else
                {
                    $enc = [System.Text.Encoding]::ASCII
                    return $enc.GetString($result)
                }
            }
        }

    }
    END {
        $rc = Set-LHSTokenPrivilege -Privilege SeSystemEnvironmentPrivilege -Disable
    }
}

# -----------------------------------------------------------------------------
# Set-UEFIVariable
# -----------------------------------------------------------------------------

function Set-UEFIVariable
{
<#
.SYNOPSIS
    Sets the value of the specified UEFI firmware variable.

.DESCRIPTION
    Sets the value of the specified UEFI firmware variable.  This must be executed in an elevated process (requires admin rights).

.PARAMETER Namespace
    A GUID string that specifies the specific UEFI namespace for the specified variable.  Some predefined namespace global variables
    are defined in this module.  If not specified, the UEFI global namespace ($UEFIGlobal) will be used.

.PARAMETER VariableName
    The name of the variable to be set.  This parameter is mandatory.  An error will be retrieved if trying to define a new variable
    in the UEFI global namespace (as per the UEFI design).

.PARAMETER Value
    The string value that should be used to set the variable value.

.PARAMETER ByteArray
    The byte array that should be used to set the variable value.

.EXAMPLE
    Set-UEFIVariable -VariableName Blah -Namespace $UEFITesting -Value Blah

.EXAMPLE
    $bytes = New-Object Byte[](8)
    Set-UEFIVariable -VariableName BlahBytes -Namespace $UEFITesting -ByteArray $bytes

.LINK
    https://oofhours.com/2019/09/02/geeking-out-with-uefi/

    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariablea

#Requires -Version 2.0
#>

    [cmdletbinding()]  
    Param(
        [Parameter()]
        [String]$Namespace = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}",

        [Parameter(Mandatory=$true)]
        [String]$VariableName,

        [Parameter()]
        [String]$Value = "",

        [Parameter()]
        [Byte[]]$ByteArray = $null
    )

    BEGIN {
        $rc = Set-LHSTokenPrivilege -Privilege SeSystemEnvironmentPrivilege
    }
    PROCESS {
        if ($Value -ne "")
        {
            $enc = [System.Text.Encoding]::ASCII
            $bytes = $enc.GetBytes($Value)
            Write-Verbose "Setting variable $VariableName to a string value with $($bytes.Length) characters"
            $rc = $uefiNative[0]::SetFirmwareEnvironmentVariableA($VariableName, $Namespace, $bytes, $bytes.Length)
        }
        else
        {
            Write-Verbose "Setting variable $VariableName to a byte array with $($ByteArray.Length) bytes"
            $rc = $uefiNative[0]::SetFirmwareEnvironmentVariableA($VariableName, $Namespace, $ByteArray, $ByteArray.Length)
        }
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($rc -eq 0)
        {
            Write-Error "Unable to set variable $VariableName from namespace $Namespace, last error = $lastError"
        }
    }
    END {
        $rc = Set-LHSTokenPrivilege -Privilege SeSystemEnvironmentPrivilege -Disable
    }

}

function Get-UEFISecureBootCerts {
<#
.SYNOPSIS
    Gets details about the UEFI Secure Boot-related variables.

.DESCRIPTION
    Gets details about the UEFI Secure Boot-related variables (db, dbx, kek, pk).

.PARAMETER Variable
    The UEFI variable to retrieve (defaults to db)

.EXAMPLE
    Get-UEFISecureBootCerts

.EXAMPLE
    Get-UEFISecureBootCerts -db

.EXAMPLE
    Get-UEFISecureBootCerts -dbx

.LINK
    https://oofhours.com/2021/01/19/uefi-secure-boot-who-controls-what-can-run/

#Requires -Version 2.0
#>        
    [cmdletbinding()]
    Param (
        [Parameter()]
        [String]$Variable = "db"
    )
    BEGIN {
        $EFI_CERT_X509_GUID = [guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
        $EFI_CERT_SHA256_GUID = [guid]"c1c41626-504c-4092-aca9-41f936934328"
    }
    PROCESS {
        $db = (Get-SecureBootUEFI -Name $variable).Bytes

        $o = 0

        while ($o -lt $db.Length)
        {
            $guidBytes = $db[$o..($o + 15)]
            [Guid] $guid = [Byte[]]$guidBytes
            $signatureListSize = [BitConverter]::ToUInt32($db, $o + 16)
            $signatureHeaderSize = [BitConverter]::ToUInt32($db, $o + 20)
            $signatureSize = [BitConverter]::ToUInt32($db, $o + 24)
            $signatureCount = ($signatureListSize - 28) / $signatureSize 
            # Write-Host "GUID: $guid"
            # Write-Host "SignatureListSize: $signatureListSize"
            # Write-Host "SignatureHeaderSize: $signatureHeaderSize"
            # Write-Host "SignatureSize: $signatureSize"
            # Write-Host "SignatureCount: $signatureCount"

            $so = $o + 28
            1..$signatureCount | % {

                $ownerBytes = $db[$so..($so+15)]
                [Guid] $signatureOwner = [Byte[]]$ownerBytes
                # Write-Host "SignatureOwner: $signatureOwner"

                if ($guid -eq $EFI_CERT_X509_GUID) {
                    $certBytes = $db[($so+16)..($so+16+$signatureSize-1)]
                    if ($PSEdition -eq "Core") {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certBytes
                    } else {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $cert.Import([Byte[]]$certBytes)
                    }
                    [PSCustomObject] @{
                        SignatureOwner = $signatureOwner
                        SignatureSubject = $cert.Subject
                        Signature = $cert
                        SignatureType = $guid
                    }
                }
                elseif ($guid -eq $EFI_CERT_SHA256_GUID) {
                    $sha256hash = ([Byte[]] $db[($so+16)..($so+48-1)] | % {$_.ToString('X2')} ) -join ''
                    [PSCustomObject] @{
                        SignatureOwner = $signatureOwner
                        Signature = $sha256Hash
                        SignatureType = $guid
                    }
                }
                else {
                    Write-Warning "Unable to decode EFI signature type: $guid"
                }

                $so = $so + $signatureSize
            }

            $o = $o + $signatureListSize
        }

    }
}

function Get-UEFIBootEntry {
<#
.SYNOPSIS
    Gets the specified UEFI boot entry, or all boot entries if no ID is specified.

.DESCRIPTION
     Gets the specified UEFI boot entry, or all boot entries if no ID is specified.  Items are returned in the order they occur in the boot order.  This must be executed in an elevated process (requires admin rights).

.PARAMETER ID
    Specifies the boot entry to display (e.g. Boot0001).

.PARAMETER Hidden
    Switch to specify that hidden boot entries should be shown (only used when ID is not specified).

.PARAMETER FilePaths
    Switch to specify that the file path details should be returned with each boot entry.

.EXAMPLE
    Get-UEFIBootEntry

.EXAMPLE
    Get-UEFIBootEntry -Hidden

.EXAMPLE
    Get-UEFIBootEntry -ID Boot0001

.EXAMPLE
    Get-UEFIBootEntry -ID Boot0001 -FilePaths

.OUTPUTS
    A set of objects representing the boot entries.

.LINK
    https://oofhours.com/2019/09/02/geeking-out-with-uefi/

#Requires -Version 2.0
#>

    [cmdletbinding()]  
    Param(
        [Parameter(ParameterSetName='ID', Mandatory = $false)]
        [String]$ID = "",
        [switch]$Hidden = $false,
        [switch]$FilePaths = $false
    )

    PROCESS {
        # Get the list of boot entries
        $bootEntries = @()
        if ($ID -eq "") {
            $bootOrder = Get-UEFIVariable -VariableName BootOrder -AsByteArray
            for ($i = 0; $i -lt $bootOrder.Length; $i = $i + 2) {
                $entry = [System.BitConverter]::ToInt16($bootOrder, $i)
                $bootEntries += "Boot" + ([System.Convert]::ToString($entry, 16)).PadLeft(4, '0').ToUpper()
            }
        } else {
            $bootEntries += $ID
        }

        # Process the list
        $bootEntries | % {
            $bytes = Get-UEFIVariable -VariableName $_ -AsByteArray
            # First four bytes are the attributes, next two are the length of the file path list
            $attrib = [System.BitConverter]::ToInt32($bytes, 0)
            $filePathListLength = [System.BitConverter]::ToInt16($bytes, 4)
            # See if this is a hidden entry
            if ($attrib -band 8) { $isHidden = $true } else { $isHidden = $false }
            if ($Hidden -or (-not $isHidden)) {
                # Get the description (cheat by getting a null-terminated string from the beginning of a full string)
                $descriptionString = [System.Text.Encoding]::Unicode.GetString($bytes[6..($bytes.Length-1)])
                $description = ($descriptionString -Split [char]0x0000)[0]
                # Get the file list path start
                $currentStart = 6 + ($description.Length + 1) * 2
                $optionStart = $currentStart + $filePathListLength
                $filePathEntries = @()
                while ($currentStart -lt $optionStart) {
                    # Get the basics
                    $type = [int]$bytes[$currentStart + 0]
                    $subtype = [int]$bytes[$currentStart + 1]
                    $filePathLength = [System.BitConverter]::ToInt16($bytes, $currentStart + 2)
                    $filePath = ""
                    $filePathRaw = ""
                    if ($filePathLength -gt 4) {
                        $filePathString = [System.Text.Encoding]::Unicode.GetString($bytes[($currentStart+4)..($bytes.Length-1)])
                        $filePath = ($filePathString -Split [char]0x0000)[0]
                        $filePathRaw = $bytes[($currentStart+4)..($currentStart+$filePathLength-1)]
                    }
                    # Depending on the type and subtype, decode further
                    $extra = [ordered]@{}
                    $typeName = "Unknown ($type-$subtype)"
                    if (($type -eq 1) -and ($subtype -eq 1)) {
                        $typeName = "PCI"
                        $pciFunction = [int]$filePathRaw[0]
                        $pciDevice = [int]$filePathRaw[1]
                        $extra["DevicePath"] = "PciRoot(0)/PCI($pciDevice/$pciFunction)"
                    } elseif (($type -eq 1) -and ($subtype -eq 4)) {
                        $typeName = "Vendor"
                        $extra["VendorGUID"] = [Guid]::new([byte[]]$filePathRaw[0..15])
                        $extra["VendorData"] = $filePathRaw[16..$filePathLength]
                        $extra["VendorDataString"] = [System.Text.Encoding]::Unicode.GetString($filePathRaw[16..$filePathLength])
                    } elseif (($type -eq 2) -and ($subtype -eq 1)) {
                        $typeName = "ACPI Device Path"
                        if (($filePathRaw[0] -eq 0xD0) -and ($filePathRaw[1] -eq 0x41)) {
                            $s = ($filePathRaw[2..3] | ForEach-Object ToString X2) -Join ""
                            $extra["DevicePath"] = "PNP$s"
                        }
                    } elseif (($type -eq 2) -and ($subtype -eq 2)) {
                        $typeName = "Expanded ACPI Device Path"
                    } elseif (($type -eq 3) -and ($subtype -eq 11)) {
                        $typeName = "MAC Address"
                        $extra["MacAddress"] = ($filePathRaw[0..5] | ForEach-Object ToString X2) -Join ""
                    } elseif (($type -eq 3) -and ($subtype -eq 12)) {
                        $typeName = "IPv4"
                    } elseif (($type -eq 3) -and ($subtype -eq 13)) {
                        $typeName = "IPv6"
                    } elseif (($type -eq 3) -and ($subtype -eq 24)) {
                        $typeName = "URI"
                        $extra["URI"] = [System.Text.Encoding]::ASCII.GetString($filePathRaw[0..$filePathLength])
                    } elseif (($type -eq 4) -and ($subtype -eq 1)) {
                        $typeName = "Hard Drive"
                        $extra["PartitionNumber"] = [System.BitConverter]::ToUInt32($filePathRaw, 0)
                        $extra["PartitionStart"] = [System.BitConverter]::ToUInt64($filePathRaw, 4)
                        $extra["PartitionSize"] = [System.BitConverter]::ToUInt64($filePathRaw, 12)
                        $extra["PartitionFormat"] = [int]$filePathRaw[36]
                        $extra["SignatureType"] = [int]$filePathRaw[37]
                        if ($extra["SignatureType"] -eq 0x2) {
                            $extra["PartitionSignature"] = [Guid]::new([byte[]]$filePathRaw[20..35])
                        } else {
                            $extra["PartitionSignature"] = $filePathRaw[20..35]
                        }
                    } elseif (($type -eq 4) -and ($subtype -eq 4)) {
                        $typeName = "Media Device Path"
                        $extra["PathName"] = $filePath
                    } elseif (($type -eq 127) -and ($subtype -eq 1)) {
                        $typeName = "End of Device Path Instance"
                    } elseif (($type -eq 127) -and ($subtype -eq 255)) {
                        $typeName = "End of Entire Device Path"
                    }
                    # Add the entry to the list
                    $props = [ordered]@{
                        Type = $type
                        Subtype = $subtype
                        TypeName = $typeName
                        FilePath = $filePath
                        FilePathRaw = $filePathRaw
                    }
                    $props += $extra
                    $filePathEntries += [PSCustomObject] $props
                    $currentStart += $filePathLength
                }
                if ($FilePaths) {
                    [PSCustomObject] @{
                        ID = $_
                        Description = $description
                        Hidden = $isHidden
                        FilePaths = $filePathEntries
                    }
                } else {
                    [PSCustomObject] @{
                        ID = $_
                        Description = $description
                        Hidden = $isHidden
                    }
                }
            }
        }
    }
}

function Add-UEFIBootEntry {
    <#
    .SYNOPSIS
        Adds a new UEFI boot entry to the list of boot entries.
    
    .DESCRIPTION
        Adds a new UEFI boot entry to the list of boot entries.  This new entry is added to the beginning of the boot order.  This must be executed in an elevated process (requires admin rights).
    
    .PARAMETER Name
        Specifies the name that should be assigned to the boot entry.  This will be displayed in the firmware boot menu.

    .PARAMETER AddAtEnd
        Switch that specifies that the new boot entry should be added to the end of the list instead of the beginning.
    
    .PARAMETER FilePath
        Specifies the relative path of the boot file (which must be on a FAT32 system volume) that the firmware should try to load when booting using this boot entry.
    
    .PARAMETER DiskNumber
        Specifies the (optional) disk number that the boot file will be placed on.  By default, the disk will be automatically determined as long as there is only one FAT32 system volume.
    
    .PARAMETER PartitionNumber
        Specifies the (optional) partition number that the boot file will be placed on.  By default, the current system partition on the selected disk will be chosen.
    
    .PARAMETER PartitionIndex
        Specifies the (optional) partition index that the boot file will be placed on.  By default, this would be the same as the partition number unless you shrunk an existing partition and created a new partition in the empty space, without rebooting.

    .PARAMETER NetworkType
        Specifies the network type (IPv4 or IPv6) to add to a new HTTP/HTTPS boot entry.

    .PARAMETER URI
        Specifies a URL to fetch for booting via HTTP/HTTP boot, e.g. "http://boot.ipxe.org/ipxe.efi".  If not specified, a DHCP request (HTTPClient) will be used to attempt to find a URL.

    .EXAMPLE
        Add-UEFIBootEntry -Name "Linux" -FilePath "\EFI\BOOT\BOOTX64.EFI"

    .EXAMPLE
        Add-UEFIBootEntry -Name "iPXE" -AddAtEnd -NetworkType IPv4 -URI http://boot.ipxe.org/ipxe.efi    

    .OUTPUTS
        The boot entry ID (e.g. Boot0001) that was assigned to the new entry.
    
    .LINK
        https://oofhours.com/2019/09/02/geeking-out-with-uefi/
    
    #Requires -Version 2.0
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]  
    Param(
        [Parameter(Mandatory=$true)][String]$Name,
        [Parameter()][switch]$AddAtEnd = $false,
        [Parameter(ParameterSetName='BootFile',Mandatory=$true)][String]$FilePath,
        [Parameter(ParameterSetName='BootFile')][int]$DiskNumber = -1,
        [Parameter(ParameterSetName='BootFile')][int]$PartitionNumber = -1,
        [Parameter(ParameterSetName='BootFile')][int]$PartitionIndex = -1,
        [Parameter(ParameterSetName='BootURI',Mandatory=$true)][ValidateSet("IPv4","IPv6")][string]$NetworkType,
        [Parameter(ParameterSetName='BootURI')][string]$URI
    )

    PROCESS {
        # Get a new boot entry ID
        $id = "Invalid"
        $idNum = -1
        for ($i = 0; $i -lt 9999; $i++) {
            $id = "Boot" + ([System.Convert]::ToString($i, 16)).PadLeft(4, '0').ToUpper()
            $b = Get-UEFIVariable -VariableName $id -ErrorAction SilentlyContinue
            if ($b -eq "") {
                $idNum = $i
                break
            }
        }
        
        $size = 1024
        $bytes = New-Object Byte[]($size)

        if ($PSCmdlet.ParameterSetName -eq "BootFile")
        {
            # Get the partition
            if ($DiskNumber -gt -1 -and $PartitionNumber -gt -1) {
                $part = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber
            } elseif ($DiskNumber -eq -1) {
                $part = Get-Partition | ? { $_.Type -eq 'System' }
            } else {
                $part = Get-Partition -DiskNumber $DiskNumber | ? { $_.Type -eq 'System' }
            }
            $disk = $part | Get-Disk
            # Assemble the entry header
            # Attributes: 4 bytes
            $bytes[0] = 1
            # File path list length: two bytes, added later
            # Add the description
            $null = [System.Text.Encoding]::Unicode.GetBytes($Name, 0, $Name.Length, $bytes, 6)
            $descriptionLength = ($Name.Length + 1) * 2
            $offset = 6 + $descriptionLength
            # Add the hard drive file path
            $bytes[$offset] = 4
            $bytes[$offset+1] = 1
            $bytes[$offset+2] = 42
            $bytes[$offset+3] = 0
            if ($PartitionIndex -gt -1) {
                $pn = [System.BitConverter]::GetBytes([uint32]$PartitionIndex)
            } else {
                $pn = [System.BitConverter]::GetBytes([uint32]$part.PartitionNumber)
            }
            $pn.CopyTo($bytes, $offset+4)
            $partOffset = $part.Offset / $disk.LogicalSectorSize
            $po = [System.BitConverter]::GetBytes([uint64]$partOffset)
            $po.CopyTo($bytes, $offset+8)
            $size = $part.Size / $disk.LogicalSectorSize
            $ps = [System.BitConverter]::GetBytes([uint64]$size)
            $ps.CopyTo($bytes, $offset+16)
            $psig = ([guid]$part.Guid).ToByteArray()
            $psig.CopyTo($bytes, $offset+24)
            $bytes[$offset+40] = 2  # GPT
            $bytes[$offset+41] = 2  # GUID signature
            # Add the media device path
            $bytes[$offset+42] = 4
            $bytes[$offset+43] = 4
            # Media device path length = 4 + length
            $dpLen = 4 + ($FilePath.Length + 1) * 2
            $dp = [System.BitConverter]::GetBytes([uint16]$dpLen)
            $dp.CopyTo($bytes, $offset + 44)
            # Set path
            $null = [System.Text.Encoding]::Unicode.GetBytes($FilePath, 0, $FilePath.Length, $bytes, $offset+46)
            $newOffset = $offset + 46 + ($FilePath.Length + 1) * 2
            # End the list
            $bytes[$newOffset] = 127
            $bytes[$newOffset+1] = 255
            $bytes[$newOffset+2] = 4
            $bytes[$newOffset+3] = 0
            # Set the file path list size
            $filePathListLength = ($newOffset+4) - (6 + $descriptionLength)
            $ll = [System.BitConverter]::GetBytes([uint16]$filePathListLength)
            $ll.CopyTo($bytes, 4)
            # Resize to the actual size
            [System.Array]::Resize([ref] $bytes, $newOffset+4)
        } elseif ($PSCmdlet.ParameterSetName -eq "BootURI") {
            # We can find a network boot entry using the right type (3) and subtype (12=IPv4, 13=IPv6)
            $subtype = 12
            if ($NetworkType -eq "IPv6") { $subtype = 13 }
            # Find a network entry of the right type
            $foundEntry = $null
            Get-UEFIBootEntry -FilePaths | ForEach-Object {
                $match = $_.FilePaths | ? { $_.Type -eq 3 -and $_.Subtype -eq $subtype }
                if ($null -ne $match) {
                    # Found a network entry of the right type, see if it has a MAC address.
                    $match = $_.FilePaths | ? { $_.Type -eq 3 -and $_.Subtype -eq 11 }
                    if ($null -ne $match) {
                        # Found a MAC address, make sure it doesn't already have a URI
                        $match = $_.FilePaths | ? { $_.Type -eq 3 -and $_.Subtype -eq 24 }
                        if ($null -ne $match) {
                            # Nope, this entry already has a URI associated with it
                        } elseif ($null -eq $foundEntry) {
                            $foundEntry = $_
                            Write-Verbose "Cloning $($foundEntry.ID) to create new entry"
                        } else {
                            Write-Warning "Multiple matching boot entries were found, using only the first, $($foundEntry.ID)"
                        }
                    }
                }
            }
            if ($null -eq $foundEntry) {
                throw "Unable to find a PXE boot entry to copy, can't continue"
            }
            # Now let's construct a new entry
            # Attributes: 4 bytes
            $bytes[0] = 1
            # File path list length: two bytes, added later
            # Add the description
            $null = [System.Text.Encoding]::Unicode.GetBytes($Name, 0, $Name.Length, $bytes, 6)
            $descriptionLength = ($Name.Length + 1) * 2
            $offset = 6 + $descriptionLength
            # Copy the file path items except for the end of list (chop off last four bytes)
            $foundEntry.FilePaths | ForEach-Object {
                if ($_.Type -eq 127 -and $_.Subtype -eq 255) {
                    # Ignore the end indicator, we'll add that later
                } else {
                    $bytes[$offset] = $_.Type
                    $bytes[$offset+1] = $_.Subtype
                    $fpLen = [System.BitConverter]::GetBytes([uint16]$_.FilePathRaw.Length + 4)
                    $fpLen.CopyTo($bytes, $offset + 2)
                    $offset = $offset + 4
                    $_.FilePathRaw.CopyTo($bytes, $offset)
                    $offset = $offset + $_.FilePathRaw.Length
                }
            }
            # Add the URI
            $bytes[$offset] = 3
            $bytes[$offset+1] = 24
            if ($URL -ne "") {
                $uriLen = 4 + $URI.Length + 1
                $uriLenBytes = [System.BitConverter]::GetBytes([uint16]$uriLen)
                $uriLenBytes.CopyTo($bytes, $offset + 2)
                $offset = $offset + 4
                $null = [System.Text.Encoding]::ASCII.GetBytes($URI, 0, $URI.Length, $bytes, $offset)
                $offset = $offset + $URI.Length + 1
            } else {
                $bytes[$offset+2] = 4
                $bytes[$offset+3] = 0
                $offset = $offset + 4             
            }
            # End the list
            $bytes[$offset] = 127
            $bytes[$offset+1] = 255
            $bytes[$offset+2] = 4
            $bytes[$offset+3] = 0
            # Set the file path list size
            $filePathListLength = ($offset+4) - (6 + $descriptionLength)
            $ll = [System.BitConverter]::GetBytes([uint16]$filePathListLength)
            $ll.CopyTo($bytes, 4)
            # Resize to the actual size
            [System.Array]::Resize([ref] $bytes, $offset+4)            
        }
        # Calculate the boot order
        $bootOrder = Get-UEFIVariable -VariableName BootOrder -AsByteArray
        $newBootOrder = New-Object Byte[]($bootOrder.Length + 2)
        if ($AddAtEnd) {
            $bootOrder.CopyTo($newBootOrder, 0)
            $newBootOrder[$bootOrder.Length] = $idNum
        } else {
            $bootOrder.CopyTo($newBootOrder, 2)
            $newBootOrder[0] = $idNum
        }
        # Save the variable and add it to the boot order
        if ($PSCmdlet.ShouldProcess($id, 'Create new boot entry')) {
            Set-UEFIVariable -VariableName $id -ByteArray $bytes
            Set-UEFIVariable -VariableName BootOrder -ByteArray $newBootOrder
        } else {
            $newBootOrder | Format-Hex
            $bytes | Format-Hex
        }
        # Return the boot entry ID
        $id
    }
}

function Remove-UEFIBootEntry {
    <#
    .SYNOPSIS
        Removes the specified UEFI boot entry.
    
    .DESCRIPTION
        Removes the specified UEFI boot entry variable and the current boot order.  This must be executed in an elevated process (requires admin rights).
    
    .PARAMETER ID
        Specifies the boot entry to remove (e.g. Boot0001).
    
    .EXAMPLE
        Remove-UEFIBootEntry -ID Boot0001
    
    .OUTPUTS
        None.
    
    .LINK
        https://oofhours.com/2019/09/02/geeking-out-with-uefi/
    
    #Requires -Version 2.0
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]  
    Param(
        [Parameter(Mandatory=$true)][String]$ID
    )

    PROCESS {
        # Get the numeric ID for the hex-encoded entry suffix
        $idNum = [int]"0x$($id.Substring(4))"
        # Calculate the (shorter) boot order
        $bootOrder = Get-UEFIVariable -VariableName BootOrder -AsByteArray
        $newBootOrder = New-Object Byte[]($bootOrder.Length - 2)
        $offset = 0
        $newOffset = 0
        While ($offset -lt $bootOrder.Length) {
            if ($bootOrder[$offset] -ne $idNum) {
                $newBootOrder[$newOffset] = $bootOrder[$offset]
                $newOffset += 2
            }
            $offset += 2
        }
        # Save the variable and add it to the boot order
        if ($PSCmdlet.ShouldProcess($id, 'Remove boot entry')) {
            Set-UEFIVariable -VariableName $id
            Set-UEFIVariable -VariableName BootOrder -ByteArray $newBootOrder
        } else {
            $newBootOrder | Format-Hex
        }
    }
}


# The following functions enable and disable the required SeSystemEnvironmentPrivilege.  It was pulled from
# Lee Holmes' blog at http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/.  This
# is tremendously useful when dealing with Windows priviledges.

function Set-LHSTokenPrivilege
{
<#
.SYNOPSIS
    Enables or disables privileges in a specified access token.

.DESCRIPTION
    Enables or disables privileges in a specified access token.

.PARAMETER Privilege
    The privilege to adjust. This set is taken from
    http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx

.PARAMETER ProcessId
    The process on which to adjust the privilege. Defaults to the current process.

.PARAMETER Disable
    Switch to disable the privilege, rather than enable it.

.EXAMPLE
    Set-LHSTokenPrivilege -Privilege SeRestorePrivilege

    To set the 'Restore Privilege' for the current Powershell Process.

.EXAMPLE
    Set-LHSTokenPrivilege -Privilege SeRestorePrivilege -Disable

    To disable 'Restore Privilege' for the current Powershell Process.

.EXAMPLE
    Set-LHSTokenPrivilege -Privilege SeShutdownPrivilege -ProcessId 4711
    
    To set the 'Shutdown Privilege' for the Process with Process ID 4711

.INPUTS
    None to the pipeline

.OUTPUTS
    System.Boolean, True if the privilege could be enabled

.NOTES
    to check privileges use whoami
    PS:\> whoami /priv

    PRIVILEGES INFORMATION
    ----------------------

    Privilege Name                Description                          State
    ============================= ==================================== ========
    SeShutdownPrivilege           Shut down the system                 Disabled
    SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
    SeUndockPrivilege             Remove computer from docking station Disabled
    SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled


    AUTHOR: Pasquale Lantella 
    LASTEDIT: 
    KEYWORDS: Token Privilege

.LINK
    http://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/

    The privilege to adjust. This set is taken from
    http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx

    pinvoke AdjustTokenPrivileges (advapi32)
    http://www.pinvoke.net/default.aspx/advapi32.AdjustTokenPrivileges

#Requires -Version 2.0
#>
   
[cmdletbinding(  
    ConfirmImpact = 'low',
    SupportsShouldProcess = $false
)]  

[OutputType('System.Boolean')]

Param(

    [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$False,HelpMessage='An Token Privilege.')]
    [ValidateSet(
        "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
    [String]$Privilege,

    [Parameter(Position=1)]
    $ProcessId = $pid,

    [Switch]$Disable
   )

BEGIN {

    Set-StrictMode -Version Latest
    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name

## Taken from P/Invoke.NET with minor adjustments.

$definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@



} # end BEGIN

PROCESS {

    $processHandle = (Get-Process -id $ProcessId).Handle
    
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)

} # end PROCESS

END { Write-Verbose "Function ${CmdletName} finished." }

} # end Function Set-LHSTokenPrivilege                
 