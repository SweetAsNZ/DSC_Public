# REF: https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/securemof?view=powershell-7.1
# Create a Self-Signed Cert for MOF Credential Encryption. It is recommended to NOT use ENTERPRISE Certs.

$Cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { ($_.EnhancedKeyUsageList -like '*Document Encryption*') `
 -and ($_.FriendlyName -eq 'DSC Credential Encryption Certificate') `
 -and ($_.Subject -eq "CN=${ENV:ComputerName}_DSC_Credential_Encryption_Certificate") }

$RootCert = Get-ChildItem -Path cert:\LocalMachine\Root | Where-Object { ($_.EnhancedKeyUsageList -like '*Document Encryption*') `
 -and ($_.FriendlyName -eq 'DSC Credential Encryption Certificate') `
 -and ($_.Subject -eq "CN=${ENV:ComputerName}_DSC_Credential_Encryption_Certificate") }


# Check For Certs True = Cert Exists
IF( $Cert ) {
    Write-Verbose "CERT EXISTS" -Verbose
 }

# Create it on the Target Node (DSC Client) and export just the public key to the Authoring Node (e.g. Jump Hosts)

# ON THE TARGET NODE: create and export the certificate in an Admin PS Session
# $Cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName 'DscEncryptionCert' -HashAlgorithm SHA256
IF(! ($Cert) )  {
    Write-Verbose "CERT DOES NOT EXIST" -Verbose
    New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName "$ENV:COMPUTERNAME" -HashAlgorithm SHA256 -FriendlyName 'DSC Credential Encryption Certificate'`
 -NotAfter (Get-Date).AddDays(365) -Subject "CN=${ENV:ComputerName}_DSC_Credential_Encryption_Certificate" # The type must remain DocumentEncryptionCertLegacyCsp see Ref: above
 }
 
$Cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { ($_.EnhancedKeyUsageList -like '*Document Encryption*') `
 -and ($_.FriendlyName -eq 'DSC Credential Encryption Certificate') `
 -and ($_.Subject -eq "CN=${ENV:ComputerName}_DSC_Credential_Encryption_Certificate") }

# Export Public key To Disk
$Output       = "C:\SCRIPTS\DSC\$($ENV:COMPUTERNAME)\DSC_Client_MOF_Encryption_Cert_PublicKey.cer"
$OutputFolder = (Split-Path -Path $Output -Parent)
if(-not (Test-Path -Path $OutputFolder) ){
    
    Write-Output "Creating `$Output Folder"
    New-Item -Path $OutputFolder -ItemType Directory
}
if(Test-Path -Path $OutputFolder){
    
    Write-Output "Creating Cert File"
    $Cert | Export-Certificate -FilePath $Output -Force  # This is used by the Import Below
}

# ON THE TARGET AND AUTHORING NODE
# Import Certificate with Public Key into Trusted Root Certificate Authorities Store so Cert is Trusted. $_.Verify() below will fail if this is not done.
Import-Certificate -FilePath $Output -CertStoreLocation Cert:\LocalMachine\Root


# Check the certificate that works for encryption
function Get-LocalEncryptionCertificateThumbprint
{
    (Get-ChildItem Cert:\LocalMachine\my) | ForEach-Object{
        # Verify the certificate is for Encryption and valid
        if ($_.PrivateKey.KeyExchangeAlgorithm -and $_.FriendlyName -eq 'DSC Credential Encryption Certificate' -and $_.Verify() -and $_.Subject -eq "CN=${ENV:ComputerName}_DSC_Credential_Encryption_Certificate" ) 
        {
            return $_.Thumbprint
        }
    }
}
Get-LocalEncryptionCertificateThumbprint