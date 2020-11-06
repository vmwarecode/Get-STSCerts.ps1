<#
    .NOTES
        Author: Mark McGill, VMware
        Last Edit: 11-6-2020
        Version 1.1
    .SYNOPSIS
        Returns vCenter certificate information for the Security Token Service signing certificate
    .DESCRIPTION
        Returns valid from and valid to dates for the STS certificates. See https://kb.vmware.com/s/article/79248
        vCenter and user are required. If no password is specified, you will be prompted for one
        User must be a local user to vCenter, and must be in SPN format (user@domain.com)
    .PARAMETER vcenters
        REQUIRED
        A single vCenter or array of vCenters to query
    .PARAMETER user
        REQUIRED
        vSphere local domain user in SPN format (ie, administrator@vsphere.local). Local user is needed in order to query LDAP
    .PARAMETER password
        If you do not specify a password when calling the function, you will be prompted for it
    .EXAMPLE
        #load function and run
        . ./Get-STSCerts.ps1
        Get-STSCerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -password 'VMware1!'
    .EXAMPLE
        #uses an array to pass multiple vcenters to the function
        $vCenters = "vCenter1.domain.com","vcenter2.domain.com","vCenter3.domain.com"
        $vCenters | Get-STSCerts -user "administrator@vsphere.local" -password 'VMware1!'
    .EXAMPLE
        #pull vCenter names from a text file (1 vCenter name per line)
        Get-Content "C:\test\vCenters.txt" | Get-STSCerts -user "administrator@vsphere.local"
    .OUTPUTS
        Array of objects containing certificate Valid From, Valid To, Subject, and Issuer
#>

function Get-STSCerts
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$vcenters,
        [Parameter(Mandatory=$true)]$user,
        [Parameter(Mandatory=$false)]$password
    )
    Begin
    {
        $userName = $user.Split("@")[0]
        $domain = ($user.Split("@")[1]).Split(".")
        $userDN = "cn=$userName,cn=users,dc=$($domain[0]),dc=$($domain[1])"
        $basedn = "cn=TenantCredential-1,cn=$($domain[0]).$($domain[1]),cn=Tenants,cn=IdentityManager,cn=Services,dc=$($domain[0]),dc=$($domain[1])"
    
        If($password -eq $null)
        {
            $securePassword = Read-Host -Prompt "Enter password for administrator account" -AsSecureString
        }
        Else
        {
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
        }
        Try
        {
            $creds = New-Object System.Management.Automation.PSCredential -ArgumentList $userDN, $securePassword -ErrorAction Stop
        }
        Catch
        {
            Throw "Error creating credentials for LDAP: $($_.Exception.Message)"
        }
        $certificates = @()
    } #end Begin

    Process
    {
        foreach($vcenter in $vcenters)
        {

            [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $ldapConnect = New-Object System.DirectoryServices.Protocols.LdapConnection $vcenter
            $ldapConnect.SessionOptions.SecureSocketLayer = $false
            $ldapConnect.SessionOptions.ProtocolVersion = 3
            $ldapConnect.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic

            Try 
            {
                $ErrorActionPreference = 'Stop'
                $ldapConnect.Bind($creds)
                $ErrorActionPreference = 'Continue'
                Write-Verbose "Successfully connected to LDAP"
            }
            Catch 
            {
                Throw "Error binding to LDAP on $vcenter : $($_.Exception.Message)"
            }

            $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
            $attrlist = $null
            $filter = "(objectClass=*)"

            $query = New-Object System.DirectoryServices.Protocols.SearchRequest -ArgumentList $basedn,$filter,$scope,$attrlist

            Try 
            {
                $ErrorActionPreference = 'Stop'
                $request = $ldapConnect.SendRequest($query) 
                $ErrorActionPreference = 'Continue'
            }
            Catch 
            {
                Throw "Error sending LDAP request - $($_.Exception.Message)"
            }

            $numCerts = $request.Entries.attributes['userCertificate'].Count
            foreach ($i in 0..($numCerts-1))
            {
                $certificate = "" | Select vCenter,ValidFrom,ValidTo,Subject,Issuer
                $cert = $request.Entries.attributes['userCertificate'].Item($i)
                $X509Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2(,$cert)
                #$X509Cert.Import([byte[]]$cert)
                $certificate.vCenter = $vCenter
                $certificate.ValidFrom = $X509Cert.NotBefore
                $certificate.ValidTo = $X509Cert.NotAfter
                $certificate.Subject = $X509Cert.Subject
                $certificate.Issuer = $X509Cert.Issuer
                $certificates += $certificate
            }#end foreach
        }#end foreach
    }#end Process
    End
    {
        Return $certificates
    }
}