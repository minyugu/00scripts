#region Group
$UpdatePath = "D:\Software\ADMT\Migration\Recurse\new_Updated_OU_Structure.csv"
$OUs = Import-Csv -Path $UpdatePath

foreach ($OU in $OUs )
{
    $ADGroupCount = (Get-ADGroup -Filter * -SearchBase $OU.DistinguishedName -SearchScope Subtree -Server "ad6-v-szzb.vanke.net.cn" -ErrorAction Stop).count
    $OUName = ($OU.Name -split ",")[0].Replace("OU=","")
    "$OUName,$ADGroupCount" | Out-File -FilePath "D:\Software\ADMT\Migration\Recurse\groupcount.csv" -Encoding utf8 -Append 
}
#endregion

#region User
$UpdatePath = "D:\Software\ADMT\Migration\Recurse\new_Updated_OU_Structure.csv"
$OUs = Import-Csv -Path $UpdatePath

foreach ($OU in $OUs )
{
    $ADGroupCount = (Get-ADUser -Filter * -SearchBase $OU.DistinguishedName -SearchScope Subtree -Server "ad6-v-szzb.vanke.net.cn" -ErrorAction Stop).count
    $OUName = ($OU.Name -split ",")[0].Replace("OU=","")
    "$OUName,$ADGroupCount" | Out-File -FilePath "D:\Software\ADMT\Migration\Recurse\UserCount.csv" -Encoding utf8 -Append 
}
#endregion


function creatOU
{

    $UpdatePath = "D:\Software\ADMT\Migration\Recurse\new_Updated_OU_Structure.csv"
    $OUs = Import-Csv -Path $UpdatePath

    foreach ($OU in $OUs )
    {
        New-ADOrganizationalUnit -Name $OU.Name -Path "OU=万物云,DC=onewo,DC=net,DC=cn" -ProtectedFromAccidentalDeletion ([Boolean]$OU.ProtectedFromAccidentalDeletion) -ErrorAction Stop
    }

}