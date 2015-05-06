# OUs, Gruppen und Benutzer für die Domäne M159gmbh.local per PS-Skript erstellen

#------------------------------
# OUs erstellen
write-host "++ Erstelle OUs ++"

# OU Groups erstellen
$adsi = [adsi] "LDAP://localhost:389/dc=M159gmbh, dc=local"
$east = $adsi.Create("OrganizationalUnit", "OU=Groups")
$east.SetInfo()

# UnterOUs von Groups erstellen
$adsi = [adsi] "LDAP://localhost:389/ou=Groups, dc=M159gmbh, dc=local"
$east = $adsi.Create("OrganizationalUnit", "OU=SW")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=FS")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=AB")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=AC")
$east.SetInfo()


# OU M159USERS erstellen
$adsi = [adsi] "LDAP://localhost:389/dc=M159gmbh, dc=local"
$east = $adsi.Create("OrganizationalUnit", "OU=M159USERS")
$east.SetInfo()

# UnterOUs in Users erstellen
$adsi = [adsi] "LDAP://localhost:389/ou=M159USERS, dc=M159gmbh, dc=local"
$east = $adsi.Create("OrganizationalUnit", "OU=G")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=E")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=P")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=M")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=V")
$east.SetInfo()
$east = $adsi.Create("OrganizationalUnit", "OU=B")
$east.SetInfo()

#------------------------------
# Gruppen erstellen
write-host "++ Erstelle Gruppen ++"

New-ADGroup -Name "SG-AB-G" -SamAccountName SG-AB-G -GroupCategory Security -GroupScope Global -DisplayName "SG-AB-G" -Path "OU=AB, OU=Groups, DC=M159gmbh, DC=local" -Description "Mitarbeiter GL"
New-ADGroup -Name "SG-AB-E" -SamAccountName SG-AB-E -GroupCategory Security -GroupScope Global -DisplayName "SG-AB-E" -Path "OU=AB, OU=Groups, DC=M159gmbh, DC=local" -Description "Mitarbeiter Entwicklung"
New-ADGroup -Name "SG-AB-P" -SamAccountName SG-AB-P -GroupCategory Security -GroupScope Global -DisplayName "SG-AB-P" -Path "OU=AB, OU=Groups, DC=M159gmbh, DC=local" -Description "Mitarbeiter Produktion"
New-ADGroup -Name "SG-AB-M" -SamAccountName SG-AB-M -GroupCategory Security -GroupScope Global -DisplayName "SG-AB-M" -Path "OU=AB,OU=Groups, DC=M159gmbh, DC=local" -Description "Mitarbeiter Marketing"
New-ADGroup -Name "SG-AB-V" -SamAccountName SG-AB-V -GroupCategory Security -GroupScope Global -DisplayName "SG-AB-V" -Path "OU=AB, OU=Groups, DC=M159gmbh, DC=local" -Description "Mitarbeiter Verkauf"
New-ADGroup -Name "SG-AB-B" -SamAccountName SG-AB-B -GroupCategory Security -GroupScope Global -DisplayName "SG-AB-B" -Path "OU=AB, OU=Groups, DC=M159gmbh, DC=local" -Description "Mitarbeiter Buchhaltung"
New-ADGroup -Name "SG-AC-Admin" -SamAccountName SG-AC-Admin -GroupCategory Security -GroupScope Global -DisplayName "SG-AC-Admin" -Path "OU=AC, OU=Groups, DC=M159gmbh, DC=local" -Description "Lokale Administratoren"
New-ADGroup -Name "SG-FS-Share-W" -SamAccountName SG-FS-Share -GroupCategory Security -GroupScope Global -DisplayName "SG-FS-Share" -Path "OU=FS, OU=Groups, DC=M159gmbh, DC=local" -Description "Kompletter Zugriff auf Share"
New-ADGroup -Name "SG-FS-Austausch-W" -SamAccountName SG-FS-Austausch-W -GroupCategory Security -GroupScope Global -DisplayName "SG-FS-Austausch-W" -Path "OU=FS, OU=Groups, DC=M159gmbh, DC=local" -Description "Zugriff auf Austauschordner"


#------------------------------
# Benutzer von CSV-Datei importieren und erstellen
Write-Host "++ Erstelle Benutzer ++"

$Users = Import-Csv 'S:\share\ps\user.csv' -Delimiter ';'

New-Item S:\Homes -type directory -Force

ForEach($User in $Users) {
    # Benutzer erstellen
    $setpass = ConvertTo-SecureString -AsPlainText $User.Passwort -force    
    New-ADUser -Name $User.Name -GivenName $User.Vorname -Surname $User.Nachname -SamAccountName $User.Account -UserPrincipalName $User.Mail -AccountPassword($setpass) -Path $User.Pfad  -Enabled $True -PassThru
    Add-ADGroupMember -Identity $User.Group -Member $User.Account
    Add-ADGroupMember -Identity SG-FS-Austausch-W -Member $User.Account

    Set-ADUser $User.Account -ScriptPath cores.cmd
    
    # Homeverzeichnis erstellen und freigeben
    $HomePath = $user.Account
    New-Item "S:\Homes\$HomePath" -type directory -Force
    
    $Share=[WMICLASS]”WIN32_Share”    
    $Share.Create(“S:\Homes\$HomePath”, $user.Account,0)
    
    Grant-SmbShareAccess -Name $HomePath -AccountName $User.Account -AccessRight Change -Force
    # Grant-SmbShareAccess -Name $HomePath -AccountName Administrator -AccessRight Full -Force
    Grant-SmbShareAccess -Name "S\Homes\cleutwiler" -AccountName cleutwiler -AccessRight Change -Force
}


#------------------------------
# Shares einrichten
Write-Host "++ Richte Shares ein ++"

$Shares = Import-Csv 'S:\share\ps\share.csv' -Delimiter ';'


ForEach($Dir in $Shares) {
    Write-Host $Dir.Name  
    New-Item $Dir.Path -type directory -Force
    
    #$Share=[WMICLASS]”WIN32_Share”    
    #$Share.Create($Dir.Path, $Dir.Name,0)
    
   # Revoke-SmbShareAccess $Dir.Name -AccountName "Jeder" -Force
    #Grant-SmbShareAccess -Name $Dir.Name -AccountName $Dir.AccountName -AccessRight $Dir.AccessRight -Force
    #Grant-SmbShareAccess -Name $Dir.Name -AccountName Administrator -AccessRight Full -Force
}
