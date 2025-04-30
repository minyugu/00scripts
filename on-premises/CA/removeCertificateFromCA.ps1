# v1.1
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/decommission-enterprise-certification-authority-and-remove-objects#step-6---remove-ca-objects-from-active-directory
#

$machineCAName = "corp-ca-01\OMG Root"
$outFilePath = "c:\tools\expriedCerts.csv"
$offsetToday = 366
$expireDate = $(((Get-Date).AddDays($offsetToday)).ToString($(Get-culture).DateTimeFormat.ShortDatePattern))

# get expired certificate
$expriedCerts = `
    (certutil -config $machineCAName -out "Request Disposition,Revocation Date,Certificate Expiration Date,Certificate Effective Date,Certificate Template,Issued Common Name,Issued Email Address,SerialNumber,Issued Request ID" -view csv) | ConvertFrom-Csv | `
        Where-Object {$_."Request Disposition" -eq "20 -- Issued" -and $_."Certificate Template" -ne "CAExchange"} | `
        Where-Object {[DateTime]$_."Certificate Expiration Date" -lt $expireDate}

# $expiredCerts | Out-File $outFilePath
$expriedCerts | ConvertTo-Csv | Out-File $outFilePath

# revoke cert
foreach ($expriedCert in $expriedCerts)
{
    certutil -config $machineCAName -revoke $expriedCert.'Serial Number' "6"
}

# show revoked cert
(certutil -config $machineCAName -out "Request Disposition,Revocation Date,Certificate Expiration Date,Certificate Effective Date,Certificate Template,Issued Common Name,Issued Email Address,SerialNumber,Issued Request ID" -view csv) | ConvertFrom-Csv | `
    Where-Object {$_."Request Disposition" -eq "21 -- Revoked" -and $_."Certificate Template" -ne "CAExchange"}

# remove cert
foreach ($expriedCert in $expriedCerts)
{
    certutil -config "corp-ca-01\OMG Root" –deleterow $($expriedCert.'Issued Request ID')
}

certutil –config – -ping


# clear CA in AD=================================
# clear CA in AD=================================

# determine whether any AD objects remain
# ldifde -r "cn=OMG Root" -d "CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=omygu,DC=com" -f remainingCAobjects.ldf
# ldifde -i -f c:\tools\remainingCAobjects.ldf.txt -j c:\tools\ldifde.log



# Delete certificates published to the NtAuthCertificates object
certutil -viewdelstore -? | findstr "CN=NTAuth"

certutil -viewdelstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=omygu,DC=com?cACertificate?base?objectClass=certificationAuthority"
certutil -viewdelstore "ldap:///CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=omygu,DC=com?cACertificate?base?objectclass=pKIEnrollmentService"

# dsstore -dcmon
certutil -dcinfo deleteBad
