#############################
# Prerequisites
#############################
# - The server that this script runs on must already have the:
#    - Sharepoint 2013 .img file extracted to C:\SHAREPT\SP2013Installer
#    - The Sharepoint prerequisites installed and rebooted (twice to complete)
# - A domain server must already exist
# - The farm accounts must already exist and be placed in the Domain Admins group
# - The SQL Server must already exist and be reachable
# - The DOMAIN\Administrator on the account must be added as a "Login" to the 
#     SQL Server have the following server roles assigned:
#     dbcreator, public, securityadmin, sysadmin  

#############################
# Setup Data Points
#############################
$DOMAIN = $Env:USERDOMAIN

# Must be in "named instance" format
$SQL_Server = "CMU-SQL\SQL12"

$files_path = "C:\SHAREPT"
$repo_server = "http://192.168.3.2"
$config_path = "$($files_path)\config.xml"
$pid_key = "NQTMW-K63MQ-39G6H-B2CH9-FRDWJ"

# Farm account info
$SPWeb_farm_account = "$($DOMAIN)\sp2013-farm"
$SPWebApp_farm_account = "$($DOMAIN)\sp2013-ap-webapp"
$SPSvcApp_farm_account = "$($DOMAIN)\sp2013-ap-service"
$farm_accounts_password = "TenB33rs!"

# Sharepoint site info
$sp_sitename = "Sharepoint Test Site"
$sp_site_desc = "Sharepoint 2013 is great"
$sp_port = "8890"
$sp_url = "http://sharepoint.irossicmu.local:$($sp_port)"
$sp_pool_name = "SharepointPool"

########################################
# Install Sharepoint
########################################
# Write the PID key into the config.xml file 
[xml]$configXML = Get-Content $config_path
$configXML.configuration.PIDKEY.value = $pid_key
$configXML.Save($config_path)

# Run the setup and wait for it to end 
Start-Process -FilePath "$($files_path)\SP2013Installer\setup.exe" -ArgumentList "/config $($files_path)\config.xml" -PassThru -Wait

#############################################
# Create the Sharepoint administration site
#############################################
# Service accounts
$accounts = @{}
$accounts.Add("SPFarm", @{"username" = $SPWeb_farm_account; "password" = $farm_accounts_password})
$accounts.Add("SPWebApp", @{"username" = $SPWebApp_farm_account; "password" = $farm_accounts_password})
$accounts.Add("SPSvcApp", @{"username" = $SPSvcApp_farm_account; "password" = $farm_accounts_password})

Foreach ($account in $accounts.keys) {
    $accounts.$account.Add(`
    "credential", `
    (New-Object System.Management.Automation.PSCredential ($DOMAIN + "\" + $accounts.$account.username), `
    (ConvertTo-SecureString -String $accounts.$account.password -AsPlainText -Force)))
}

Add-PSSnapin Microsoft.SharePoint.PowerShell

# Setup the info for the Central Configuration Site
$configPassphrase = "SharePoint 2013 is the latest version of SharePoint!"
$s_configPassphrase = (ConvertTo-SecureString -String $configPassphrase -AsPlainText -force)
$dbConfig = "SP2013_Configuration"
$dbCentralAdmin = "SP2013_Content_CentralAdministration"
$caPort = 11111
$caAuthProvider = "NTLM"

# The account used to execute this command must be have the following server roles in SQL SERVER:
# dbcreator, public, securityadmin, sysadmin  
# The DatabaseServer option must be specified as a named instance, SERVERNAME\INSTANCENAME
Write-Output "Creating the configuration database $dbConfig"
New-SPConfigurationDatabase -DatabaseName $dbConfig -DatabaseServer $SQL_Server -AdministrationContentDatabaseName $dbCentralAdmin -Passphrase $s_configPassphrase -FarmCredentials $accounts.SPFarm.credential

# Create the central administration site
Write-Output "Create the Central Administration site on port $caPort"
New-SPCentralAdministration `
-Port $caPort `
-WindowsAuthProvider $caAuthProvider

###########################################
# Create the Sharepoint site
###########################################
# A couple of variables needed to create the Sharepoint site
$allowAnonymous = $true
$ap = New-SPAuthenticationProvider

# Create new application in the default app pool
New-SPWebApplication -Name $sp_sitename -HostHeader "" -URL $sp_url -ApplicationPool $sp_pool_name -ApplicationPoolAccount (Get-SPManagedAccount $SPWeb_farm_account) -DatabaseName "WSS_Content_$($sp_port)" -DatabaseServer $SQL_Server -AllowAnonymousAccess -AuthenticationProvider $ap -AuthenticationMethod "NTLM"

# Create the new site
New-SPSite "$($sp_url)/sites/sharepoint" -OwnerAlias $SPWeb_farm_account -SecondaryOwnerAlias $SPWeb_farm_account -name $sp_sitename -Description $sp_site_desc

###############################
# Complete
###############################
# At this point, the domain admin needs to log into the Central administration site 
# at http://localhost:1111 and set the "User Policy" section to give access to domain groups