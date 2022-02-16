# REF: https://mehic.se/2018/12/24/install-remote-desktop-services-2016-with-desired-state-configuration/
# REF: https://docs.microsoft.com/en-us/powershell/scripting/dsc/pull-server/pullclientconfigid?view=powershell-7.1
# REF: https://docs.microsoft.com/en-us/powershell/scripting/dsc/managing-nodes/metaconfig?view=powershell-7.1


# Get the certificate thumbprint that works for MOF password decryption
function Get-LocalEncryptionCertificateThumbprint
{
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()] 
        [string[]]$ComputerName
    )

    if($ComputerName -eq $env:COMPUTERNAME){
        (Get-ChildItem Cert:\LocalMachine\my) | ForEach-Object{
            # Verify the certificate is for Encryption and valid
            if ($_.PrivateKey.KeyExchangeAlgorithm -and $_.FriendlyName -eq 'DSC Credential Encryption Certificate' -and $_.Verify()`
                -and $_.Subject -eq "CN=${ComputerName}_DSC_Credential_Encryption_Certificate" ) 
            {
                return $_.Thumbprint
            }#END IF LITTLE
        }
    }#END IF BIG
    
    # If the $Server is not the Local Server it should be a Jump Host that you are authoring on and therefore doesn't have the Private Key and Uses the Root Cert Store.
    if($ComputerName -ne $env:COMPUTERNAME){
        (Get-ChildItem Cert:\LocalMachine\Root) | ForEach-Object{
            # Verify the certificate is for Encryption and valid
            if ( $_.Verify() -and $_.Subject -eq "CN=${Server}_DSC_Credential_Encryption_Certificate" ) 
            {
                return $_.Thumbprint
            }
        }
    }#END IF BIG

}#END FUNCTION
Get-LocalEncryptionCertificateThumbprint 


[DscLocalConfigurationManager()]

Configuration LCM {
 
param (
 
[parameter(Mandatory=$true)]
[string[]]$ComputerName
)
 
    node $ComputerName {
 
        Settings {
        ActionAfterReboot     = 'ContinueConfiguration'   
        AllowModuleOverwrite  = $true
        CertificateID         = 'xxx'   # Thumbprint - Required to decrypt passwords in MOF file.
        ConfigurationMode     = 'ApplyAndAutoCorrect'
        RefreshMode           = 'Push'                                       # 'Push', 'Pull', 'Disabled'
        RefreshFrequencyMins  = 30                                           # Push Mode Refresh Default is 30 mins, may also be the minimum
        RebootNodeIfNeeded    = $true
        DebugMode             = 'All'                                        # 'All', 'ForceModuleImport', 'None'
        }
    }
}
 
$ComputerName = 'Server1' #'Server2','Server3'
 
LCM -OutputPath 'C:\SCRIPTS\DSC' -ComputerName $ComputerName -Verbose