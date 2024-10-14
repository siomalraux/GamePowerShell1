$level=0

function New-Level {
    param([String]$instruction,[String]$solution)
    $password = ConvertTo-SecureString $solution -AsPlainText -Force
    $Script:level++
    $l=$Script:level
    New-LocalUser "level$l" -Password $password -PasswordNeverExpires -UserMayNotChangePassword | Add-LocalGroupMember Administrateurs
    Start-Process "cmd.exe" -Credential (New-Object management.automation.pscredential "level$l",$password) -ArgumentList "/C"
    (New-Item "C:\Users\level$l\Documents\Get-Instruction.ps1" -ItemType File).Attributes = 'Hidden'
    (New-Item "C:\Users\level$l\Documents\Get-Solution.ps1"    -ItemType File).Attributes = 'Hidden'
    (New-Item "C:\Users\level$l\Documents\Solution"            -ItemType File).Attributes = 'Hidden'
    Set-Location "C:\Users\level$($l-1)\Documents"
    $solution = "Le mot de passe pour level$l est '$solution'."
    "'Le mot de passe pour level$l est $instruction.'"                                    >> Get-Instruction.ps1
    ConvertFrom-SecureString (ConvertTo-SecureString $solution -AsPlainText) -key(1..16)  >> Solution
    '$SecureString = ConvertTo-SecureString (Get-Content Solution) -key(1..16)'           >> Get-Solution.ps1
    '$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)' >> Get-Solution.ps1
    '[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)'                    >> Get-Solution.ps1
    '[int](Get-Content C:\Users\Malus)+1 | Set-Content C:\Users\Malus'                    >> Get-Solution.ps1
}
# Désactivation de la complexité des mots de passe et Initialisation du Jeu
secedit /export /cfg secpol.cfg
(Get-Content secpol.cfg).Replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg secpol.cfg /areas SECURITYPOLICY
Remove-Item -Force secpol.cfg -Confirm:$false
(New-Item C:\Users\Malus -ItemType File).Attributes = 'Hidden'
New-Item C:\Users\level0\Documents -ItemType Directory -Force
New-Level level1 level1

# Niveau 1
$mot_compose = 'hard_','unders_','s_','_en','en_','multi_','_team' | Get-Random
Out-File "C:\Users\level$level\Documents\$mot_compose"
New-Level "le nom du fichier avec un _ a remplacer par l''edition de PowerShell (variable)" $mot_compose.Replace('_',$PSEdition.ToLower())

# Niveau 2
New-Level "le nombre de commandes de type Cmdlet" (Get-Command -CommandType Cmdlet | Measure-Object).Count

# Niveau 3
New-Level "le nombre de DLL Windows dont le nom commence par ''K''" (Get-ChildItem C:\Windows\System32\k*.dll).Count

# Niveau 4
New-Level "le numero de serie du Bios sans espace (ComputerInfo)" (Get-CimInstance -ClassName Win32_BIOS).SerialNumber.Replace(' ','')

# Niveau 5
New-Level "le ''MachineID'' dans la cle de registre ''HKLM:\SOFTWARE\Microsoft\SQMClient''" (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SQMClient").MachineID

# Niveau 6
New-Level "l''identifiant universel unique (UUID) du système Windows" (Get-CimInstance Win32_ComputerSystemProduct).UUID

# Niveau 7
New-Level "l''identifiant de securite (SID) de l''utilisateur level$level" (Get-LocalUser "level$level").SID.Value

# Niveau 8
$alea = Get-Random -Maximum 1000
Out-File "C:\Users\level$level\Documents\$alea"
New-Level "le nom de la cmdlet equivalente a ''mount'' + le nom du fichier dans Documents" "new-psdrive$alea"

# Niveau 9
New-Level "l''Adresse Mac de l''adaptateur ''Ethernet0''" (Get-NetAdapter Ethernet0).MacAddress

# Niveau 10
New-Level "l''Adresse IPv6 de l''adaptateur ''Ethernet0''" (Get-NetIPAddress -InterfaceAlias Ethernet0).IPv6Address

# Niveau 11
For($i=1;$i -lt (Get-Random -Maximum 1000);$i++) {
  $item = New-Item "C:\Users\level$level\Documents\A ranger\$(Get-Random -Maximum 1000)$i" -ItemType ('File','Directory' | Get-Random) -Force
}
New-Level "le nombre de fichiers dans les Documents ''A ranger''" (Get-ChildItem "C:\Users\level$level\Documents\A ranger" -File).Count

# Niveau 12
New-Level "le nombre de capacites Windows non presentes sur le systeme en ligne" (Get-WindowsCapability -Online | Where-Object State -eq NotPresent).Count

# Niveau 13
For($i=1;$i -lt (Get-Random -Maximum 1000);$i++) {
  (New-Item "C:\Users\level$level\Documents\Confidentiels\$(Get-Random -Maximum 1000)$i" -ItemType ('File','Directory' | Get-Random) -Force).Attributes = 'Hidden'
}
New-Level "le nombre de dossiers caches dans les Documents ''Confidentiels''" (Get-ChildItem "C:\Users\level$level\Documents\Confidentiels" -Directory -Hidden).Count

# Niveau 14
$alea = Get-Random -Maximum 1000
(New-Item "C:\Users\level$level\Documents\Coffre Fort" -Value $alea).Attributes = 'Hidden'
New-Level "la valeur de NPARA_PASSWORD a la ligne 846 du script systeme ''winrm.vbs'' + le code secret du document cache" ((Get-Content C:\windows\system32\winrm.vbs)[846].Split('"')[1] + $alea)

# Niveau 15
New-Level "le nombre de services en cours d''execution et en type de demarrage manuel" (Get-Service | Where-Object StartType -eq Manual | Where-Object Status -eq Running).Count

# Niveau 16
New-Level "le nombre de services qui dependent directement du service ''Remote Procedure Call''" (Get-Service RPCSS -DependentServices).Count

# Niveau 17
New-Level "le nombre de proprietes de l''objet ''Process''" (Get-Process | Get-Member -MemberType Properties).Count

# Niveau 18
$fourniture = 'stylo','crayon','gomme','bloc-notes','agrafeuse','trombones','ciseaux','regle','calculatrice' | Get-Random
New-Level "la fourniture sur le bureau + le nombre de variables d''environnement du système" ($fourniture + (Get-ChildItem Env:).Count)

# Niveau 19
(New-Item "C:\Users\level$level\Documents\Confidentiels\PassPhrase" -Value "éclair âpre sur l'île ô combien unique des îlots émerveillés" -Force).Attributes = 'Hidden'
New-Level "la  phrase secrete dans les Documents ''Confidentiels'', toute en MAJUSCULES et sans espace" (Get-Content "C:\Users\level$level\Documents\Confidentiels\PassPhrase").ToLower().Replace(' ','')
