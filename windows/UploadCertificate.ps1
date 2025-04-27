<#
.SYNOPSIS
Adds a certificate from a file to the Trusted Root Certification Authorities
store within a specified Group Policy Object (GPO).

.DESCRIPTION
This script imports a certificate from a specified file and adds it to the
Computer Configuration's Trusted Root Certification Authorities policy setting
within a target GPO in Active Directory.

It requires the GroupPolicy and PKI PowerShell modules, typically available
on Domain Controllers or machines with RSAT installed.

Run this script with administrative privileges on a Domain Controller or a
management server joined to the domain with appropriate GPO edit permissions.

.PARAMETER CertificatePath
The full path to the certificate file (.crt, .cer).

.PARAMETER GPOName
The display name of the Group Policy Object to modify. The GPO must already exist.

.PARAMETER DomainName
Optional: The fully qualified domain name (FQDN) of the domain. If omitted,
it attempts to use the current domain.

.EXAMPLE
.\Add-CertificateToGpo.ps1 -CertificatePath "C:\certs\my-sample-cert.crt" -GPOName "Kubernetes Trusted Certs GPO"

.EXAMPLE
.\Add-CertificateToGpo.ps1 -CertificatePath "C:\certs\another.cer" -GPOName "Default Domain Policy" -DomainName "k8stest.local"
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$CertificatePath,

    [Parameter(Mandatory=$true)]
    [string]$GPOName,

    [string]$DomainName
)

#Requires -Modules GroupPolicy, PKI

# --- Configuration ---
# Policy store within the GPO to target. Typically "Root" for Trusted Roots.
# Other options might include "CA" (Intermediate), "Trust" (Enterprise Trust), etc.
# Corresponds to registry keys under Software\Policies\Microsoft\SystemCertificates\
$PolicyStoreName = "Root"

# --- Validation and Setup ---

# Check if certificate file exists
if (-not (Test-Path -Path $CertificatePath -PathType Leaf)) {
    Write-Error "Certificate file not found at '$CertificatePath'."
    return
}

# Import the certificate object from the file
try {
    # Import-Certificate is primarily for local stores, but we need the object
    # Get-PfxCertificate can also work for .pfx, but .crt/.cer are public keys
    # We can use X509Certificate2 class directly for more control
    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $Certificate.Import($CertificatePath)
    Write-Verbose "Successfully loaded certificate object from '$CertificatePath'."
    Write-Verbose "Certificate Subject: $($Certificate.Subject)"
    Write-Verbose "Certificate Thumbprint: $($Certificate.Thumbprint)"
}
catch {
    Write-Error "Failed to load certificate from '$CertificatePath'. Error: $($_.Exception.Message)"
    return
}

# Determine domain context
if (-string::IsNullOrEmpty($DomainName)) {
    try {
        $Domain = Get-ADDomain -ErrorAction Stop
        $DomainName = $Domain.DNSRoot
        Write-Verbose "Detected current domain: $DomainName"
    }
    catch {
        Write-Error "Could not automatically determine domain. Please specify -DomainName. Error: $($_.Exception.Message)"
        return
    }
}

# Find the GPO
try {
    Write-Verbose "Attempting to find GPO '$GPOName' in domain '$DomainName'..."
    $Gpo = Get-GPO -Name $GPOName -Domain $DomainName -ErrorAction Stop
    Write-Verbose "Found GPO: Name='$($Gpo.DisplayName)', ID='$($Gpo.Id)'"
}
catch {
    Write-Error "Could not find GPO named '$GPOName' in domain '$DomainName'. Please ensure it exists. Error: $($_.Exception.Message)"
    return
}

# --- Core Logic: Modify GPO Registry Settings ---

# GPOs store certificate policies in the registry part of the GPO structure.
# The path within the GPO's registry settings corresponds to:
# Software\Policies\Microsoft\SystemCertificates\[PolicyStoreName]\Certificates\[CertificateThumbprint]

$RegistryValueName = "Blob" # The value containing the certificate data
$RegistryKeyPath = "Software\Policies\Microsoft\SystemCertificates\$PolicyStoreName\Certificates\$($Certificate.Thumbprint)"

# Get the certificate data as a byte array (DER encoded)
try {
    $CertificateBlob = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    Write-Verbose "Successfully exported certificate to byte array (Blob)."
}
catch {
    Write-Error "Failed to export certificate data (Blob). Error: $($_.Exception.Message)"
    return
}


# Set the registry value within the GPO (Computer Configuration)
try {
    Write-Verbose "Setting registry value in GPO..."
    Write-Verbose "GPO: $($Gpo.DisplayName)"
    Write-Verbose "Scope: Computer"
    Write-Verbose "Key: $RegistryKeyPath"
    Write-Verbose "Value Name: $RegistryValueName"
    Write-Verbose "Value Type: Binary"
    Write-Verbose "Value Length: $($CertificateBlob.Length) bytes"

    # Note: Set-GPRegistryValue targets HKLM or HKCU *within the GPO*, not the local machine.
    Set-GPRegistryValue -Guid $Gpo.Id `
                        -Key $RegistryKeyPath `
                        -ValueName $RegistryValueName `
                        -Value $CertificateBlob `
                        -Type Binary `
                        -Domain $DomainName `
                        -ErrorAction Stop

    Write-Host "Successfully added certificate with thumbprint $($Certificate.Thumbprint) to GPO '$($Gpo.DisplayName)' under '$PolicyStoreName' store."

}
catch {
    Write-Error "Failed to set registry value in GPO '$($Gpo.DisplayName)'. Error: $($_.Exception.Message)"
    # Consider attempting to remove the key if partially created, though Set-GPRegistryValue might handle atomicity.
    return
}

# --- Cleanup ---
# Dispose the certificate object if needed (good practice, though garbage collection usually handles it)
if ($Certificate -is [System.IDisposable]) {
    $Certificate.Dispose()
}

Write-Verbose "Script finished."
