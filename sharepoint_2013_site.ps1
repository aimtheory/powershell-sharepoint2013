

#############################
# Setup Data Points
#############################

# Domain information for farm account creation
$domain = $Env:USERDOMAIN
$domain_admin = "iarossi"
$domain_admin_pw = "Welcome123!"

# SQL Server variables
$SQL_Server_hostname = "SQL-5SFTR28QCXN"
$SQL_Server_ip = "10.115.59.195"
$SQL_Server_port = "1433"
$SQL_Server_user = "sa"
$SQL_Server_pw = "Welcome123!"
$SQL_Server_instance = "SQL-5SFTR28QCXN\MSSQLSERVER"

$pid_key = "NQTMW-K63MQ-39G6H-B2CH9-FRDWJ"

# Farm account info
$SPWeb_farm_account = "$($domain)\sp2013-farm"
$SPWebApp_farm_account = "$($domain)\sp2013-ap-webapp"
$SPSvcApp_farm_account = "$($domain)\sp2013-ap-service"
$farm_accounts_password = "TenB33rs!"

# Sharepoint info
$sp_config_passphrase = (ConvertTo-SecureString -String $"SharePoint 2013 is the latest version of SharePoint!" -AsPlainText -force)
$sp_config_db = "SP2013_Configuration"
$sp_central_admin_db = "SP2013_Content_CentralAdministration"
$sp_central_admin_port = 11111
$sp_central_admin_auth = "NTLM"
$sp_central_admin_account = ""

# Sharepoint site info
$sp_sitename = "Sharepoint Test Site"
$sp_site_desc = "Sharepoint 2013 is great"
$sp_port = "8890"
$sp_url = "http://sharepoint.irossicmu.local:$($sp_port)"
$sp_pool_name = "SharepointPool"

########################################
# Download Sharepoint Bits
########################################

$files_path = "C:\SHAREPT"
mkdir $files_path

$repo_server = "10.115.56.113"

New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\$($repo_server)\repository"

# Install 7zip to extract Sharepoint image
Copy-Item Z:\\7zip\7zip-x64.msi $files_path\7zip-x64.msi
msiexec.exe /i "C:\SHAREPT\7zip-x64.msi" /qn /norestart

# Copy and extract Sharepoint image
Copy-Item Z:\\Microsoft\Sharepoint\2013\SharePointServer_x64_en-us.img $files_path\SharePointServer_x64_en-us.img
Start-Process "C:\Program Files\7-Zip\7z.exe" `
    -ArgumentList "x C:\SHAREPT\SharePointServer_x64_en-us.img" `
    -PassThru `
    -Wait

########################################
# Install Sharepoint
########################################
$config_path = "$($files_path)\config.xml"

# Write the PID key into the config.xml file 
[xml]$configXML = Get-Content $config_path
$configXML.configuration.PIDKEY.value = $pid_key
$configXML.Save($config_path)

# Run the setup and wait for it to end 
Start-Process `
    -FilePath "$($files_path)\SP2013Installer\setup.exe" `
    -ArgumentList "/config $($files_path)\config.xml" `
    -PassThru `
    -Wait

#############################################
# Create the Sharepoint administration site
#############################################
# Service accounts
$accounts = @{}
$accounts.Add("SPFarm", @{"username" = $SPWeb_farm_account; "password" = $farm_accounts_password})
$accounts.Add("SPWebApp", @{"username" = $SPWebApp_farm_account; "password" = $farm_accounts_password})
$accounts.Add("SPSvcApp", @{"username" = $SPSvcApp_farm_account; "password" = $farm_accounts_password})

# Add the accounts to an array
Foreach ($account in $accounts.keys) {
    $accounts.$account.Add(`
        "credential", `
        (New-Object System.Management.Automation.PSCredential ($domain + "\" + $accounts.$account.username), `
        (ConvertTo-SecureString -String $accounts.$account.password -AsPlainText -Force)))
}

# Establish the domain admin credentials to create the AD accounts
$domain_admin_cred = New-Object System.Management.Automation.PSCredential -ArgumentList @($domain_admin,(ConvertTo-SecureString -String $domain_admin_pw -AsPlainText -Force))

# Create the farm accounts in the domain
Foreach $account in $accounts.keys) {
    # Create the new user command
    $new_user_cmd = "New-ADUser `
        -SamAccountName $account.username `
        -Name $account.username `
        -UserPrincipalName '$($account.username)@$($domain)' `
        -AccountPassword $account.password `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -Path 'CN=Domain Admins,DC=$($domain),DC=$($domain_ext)'"
    
    # Create the user account as the domain admin
    Invoke-Command `
        -Credential $domain_admin_cred `
        -ComputerName localhost
        -ScriptBlock { $new_user_cmd }
}

Add-PSSnapin Microsoft.SharePoint.PowerShell

# The account used to execute this command must be have the following server roles in SQL SERVER:
# dbcreator, public, securityadmin, sysadmin  
# The DatabaseServer option must be specified as a named instance, SERVERNAME\INSTANCENAME
Write-Output "Creating the configuration database $sp_config_db"
New-SPConfigurationDatabase `
    -DatabaseName $sp_config_db `
    -DatabaseServer $SQL_Server_instance `
    -AdministrationContentDatabaseName $sp_central_admin_db `
    -Passphrase $sp_config_passphrase  `
    -FarmCredentials $accounts.SPFarm.credential

# Create the central administration site
Write-Output "Create the Central Administration site on port $sp_central_admin_port"
New-SPCentralAdministration `
    -Port $sp_central_admin_port `
    -WindowsAuthProvider $sp_central_admin_auth

###########################################
# Create the Sharepoint site
###########################################
# A couple of variables needed to create the Sharepoint site
$allowAnonymous = $true
$ap = New-SPAuthenticationProvider

# Create new application in the default app pool
New-SPWebApplication `
    -Name $sp_sitename `
    -HostHeader "" `
    -URL $sp_url `
    -ApplicationPool $sp_pool_name `
    -ApplicationPoolAccount (Get-SPManagedAccount $SPWeb_farm_account) `
    -DatabaseName "WSS_Content_$($sp_port)" `
    -DatabaseServer $SQL_Server_instance `
    -AllowAnonymousAccess `
    -AuthenticationProvider $ap `
    -AuthenticationMethod "NTLM"

# Create the new site
New-SPSite `
    "$($sp_url)/sites/sharepoint" `
    -OwnerAlias $SPWeb_farm_account `
    -SecondaryOwnerAlias $SPWeb_farm_account `
    -name $sp_sitename `
    -Description $sp_site_desc

###############################
# Complete
###############################
# At this point, the domain admin needs to log into the Central administration site 
# at http://localhost:1111 and set the "User Policy" section to give access to domain groups