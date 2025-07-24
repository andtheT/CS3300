<#
Windows system auditing script
	This script is designed to allow a user to decided what aspects of the system 
		need to be audited and when. The script shows the a gui showing the available
		options for auditing as well as the location for where the output will be saved to.
		
	The process of the script are as follows:
	
	1) If the current user is in the list of admins
		and if the current user is an admin the script will prompt to continue as Admin
	2) Define global variables, like the audit folder name/location, and needed info around timestamp
	3) Input GUI
		show user the options
		Once all options have been selected the user, they hit the 'submit' button to start the auditing
	4) Show the 'form' (GUI) to the user
	5) The audit folder opens autimaticaly when done
	
	For full functionality the system this is running on needs:
	-> Windows 10/11 with powershell, and the ability to run scripts is enabled
	-> Windows Management Insturmentation Command Line (WMIC) a windows service that allows for command line system admin 
	-> Java SDK (for SCAP functionality)
#>

#1) Elevate to admin privledges
###################################################


	param([switch]$Elevated)
	
	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
	
	function Test-Admin {
		$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
		$currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	}
	
	if ((Test-Admin) -eq $false)  {
		if ($elevated) {
			
		} else {
			#restart script with admin privleges
			Start-Process powershell.exe -WindowStyle Normal -Verb RunAs -ArgumentList ('-noprofile -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
		}	
		exit
	}


#2)  Preset Variables
###################
$Audit_date = Get-Date -UFormat "%m.%d.%Y"
$Audit_folder_name = "Audit $Audit_date"
$Audit_folder_loc = "\Users\$Env:UserName\Desktop\"
$Audit_act = "$Audit_folder_loc$Audit_folder_name"

$timestamp = Get-Date -UFormat "%Y%m%d-%H%M"
$curDay = Get-Date -UFormat "%m/%d/%Y"
$weekDay = (Get-Date).DayOfWeek
$14Day = (Get-Date).AddDays(-14)

#create and format scap benchmark options

$Scap_opts = Select-String -Pattern "stream" -Path "C:\Program Files\SCAP Compliance Checker 5.10.2\options.xml"

$Scap_opts =  $Scap_opts -replace ".*:"

$junk = "</stream>"
$Scap_opts = [regex]::Replace($Scap_opts,$junk,"`n")

$junk = "                  <stream>scap_navy.navwar.niwcatlantic.scc_datastream_U_"
$Scap_opts = [regex]::Replace($Scap_opts,$junk,"")

$junk = "<summaryViewerSort2>Stream</summaryViewerSort2>       <dirStreamNameEnabled>0</dirStreamNameEnabled> "
$Scap_opts = [regex]::Replace($Scap_opts,$junk,"")

$Scap_list = $Scap_opts -split "`n"

#3) GUI - Input
###################

[System.Console]::SetWindowSize(20,10)
[Console]::SetWindowsPosition(150,20)


#GUI/Window details
Add-Type -assembly System.Windows.Forms
$Input_GUI = New-Object System.Windows.Forms.Form
$Input_GUI.Text ='Audit Input Page'
$Input_GUI.StartPosition = "Manual"
$Input_GUI.location = New-Object System.Drawing.Point(100,100)
$Input_GUI.Width = 600
$Input_GUI.Height = 400


# Labels
$System_dets = New-Object System.Windows.Forms.Label
$System_dets.Text = "System details"
$System_dets.Location = New-Object System.Drawing.Point(10,20)
$Input_GUI.Controls.Add($System_dets)

$User_dets = New-Object System.Windows.Forms.Label
$User_dets.Text = "User details"
$User_dets.Location = New-Object System.Drawing.Point(130,20)
$Input_GUI.Controls.Add($User_dets)

$Scap_ops = New-Object System.Windows.Forms.Label
$Scap_ops.Text = "SCAP Options"
$Scap_ops.Location = New-Object System.Drawing.Point(260,20)
$Input_GUI.Controls.Add($Scap_ops)

$Folder_prompt = New-Object System.Windows.Forms.Label
$Folder_prompt.Text = "Audit Folder name:"
$Folder_prompt.Location = New-Object System.Drawing.Point(10,253)
$Input_GUI.Controls.Add($Folder_prompt)

$Folder_n_def = New-Object System.Windows.Forms.Label
$Folder_n_def.Text = "Default: $Audit_folder_name"
$Folder_n_def.Location = New-Object System.Drawing.Point(310,253)
$Folder_n_def.Size = New-Object System.Drawing.Size(200, 15)
$Input_GUI.Controls.Add($Folder_n_def)

$Folder_locp = New-Object System.Windows.Forms.Label
$Folder_locp.Text = "Audit Location:"
$Folder_locp.Location = New-Object System.Drawing.Point(10,278)
$Input_GUI.Controls.Add($Folder_locp)

$Folder_loc_def = New-Object System.Windows.Forms.Label
$Folder_loc_def.Text = "Default: C:$Audit_folder_loc"
$Folder_loc_def.Location = New-Object System.Drawing.Point(310,278)
$Folder_loc_def.Size = New-Object System.Drawing.Size(200, 15)
$Input_GUI.Controls.Add($Folder_loc_def)

$Days_lab = New-Object System.Windows.Forms.Label
$Days_lab.text = "Num days to Audit"
$Days_lab.Location = New-Object System.Drawing.Point(10,300)
$Input_GUI.Controls.Add($Days_lab)

$Def_Days_lab = New-Object System.Windows.Forms.Label
$Def_Days_lab.text = "Default: 14 days (date: $14Day)"
$Def_Days_lab.Location = New-Object System.Drawing.Point(140,300)
$Def_Days_lab.Size  = New-Object System.Drawing.Size(250, 15)
$Input_GUI.Controls.Add($Def_Days_lab)

# CheckedListBoxs
$System_ListBox = New-Object System.Windows.Forms.CheckedListBox
$System_ListBox.Size = New-Object System.Drawing.Size(115, 200)
$System_ListBox.Location = New-Object System.Drawing.Point(10, 45)

$System_items = @("Virus def update", "Last quick scan", "Last Full scan", "Last backup", "Last Update", "List software", "Backup SEC logs", "Backup APP logs", "Backup SYS logs")
$System_ListBox.Items.AddRange($System_items)
$Input_GUI.Controls.Add($System_ListBox)

$User_ListBox = New-Object System.Windows.Forms.CheckedListBox
$User_ListBox.Size = New-Object System.Drawing.Size(127, 200)
$User_ListBox.Location = New-Object System.Drawing.Point(130, 45)

$User_items = @("User List","Failed Logins","Account Changes", "Boot/login Report")
$User_ListBox.Items.AddRange($User_items)
$Input_GUI.Controls.Add($User_ListBox)

$Scap_ListBox = New-Object System.Windows.Forms.CheckedListBox
$Scap_ListBox.Size = New-Object System.Drawing.Size(199, 200)
$Scap_ListBox.Location = New-Object System.Drawing.Point(260, 45)

$Scap_items = @($Scap_list)
$Scap_ListBox.Items.AddRange($Scap_items)
$Input_GUI.Controls.Add($Scap_ListBox)


# Text boxes
$Folder_name = New-Object System.Windows.Forms.TextBox
$Folder_name.Location = New-Object System.Drawing.Point(110,250)
$Folder_name.Size = New-Object System.Drawing.Size(200,20)
$Input_GUI.controls.Add($Folder_name)

$Folder_loc = New-Object System.Windows.Forms.TextBox
$Folder_loc.Location = New-Object System.Drawing.Point(110,275)
$Folder_loc.Size = New-Object System.Drawing.Size(200,20)
$Input_GUI.controls.Add($Folder_loc)

$Num_days = New-Object System.Windows.Forms.TextBox
$Num_days.Location = New-Object System.Drawing.Point(110,296)
$Num_days.Size = New-Object System.Drawing.Size(25,20)
$Input_GUI.controls.Add($Num_days)

# Submit Button
$Submit_button = New-Object System.Windows.Forms.Button
$Submit_button.Text = "Submit"
$Submit_button.Location = New-Object System.Drawing.Point(15,315)
$Submit_button.Size = New-Object System.Drawing.Size(100, 30)
$Input_GUI.Controls.Add($Submit_button)


#3) Event handling - complete audit
$Submit_button.Add_Click({
	
	# List of options selected by user
	$selectedItems = $System_ListBox.CheckedItems + $User_ListBox.CheckedItems + $Scap_ListBox.CheckedItems
	
	# update folder name or path if needed and create audit folder
	if ($Folder_name.Text -ne "") {
		$Audit_folder_name = $Folder_name.Text
	}
	
	if ($Folder_loc.Text -ne "") {
		$Audit_folder_loc = $Folder_loc.Text
	}
	
	$Audit_act = "$Audit_folder_loc$Audit_folder_name"
	New-Item -ItemType Directory -Force -Path C:$Audit_act | Out-Null
	
	if ($Aud_date -ne "") {
		$Aud_date = $14Day
	}
	else {
		$Aud_date = $Num_days.Text
	}
	
		#scap options (ran first to hopefully run smoother) -> results moved at the end
	#############
	
	#disable all scap benchmarks
	Start-Process -FilePath "C:\Program Files\SCAP Compliance Checker 5.10.2\cscc" -ArgumentList "--disableAll" -NoNewWindow -Wait
	
	#boolean true if benchmark selected
	$scap_bool = $false
	
	if ($selectedItems -eq " MS_Windows_11_V2R3_STIG_SCAP_1-3_Benchmark-enhancedV9") {
		Start-Process -FilePath "C:\Program Files\SCAP Compliance Checker 5.10.2\cscc" -ArgumentList "--enableBenchmark Microsoft_Windows_11_STIG" -NoNewWindow -Wait
		$scap_bool = $true
	}
	
	#if boolean set to true (a scap option was selected) -> run scan
	if ($scap_bool) {
		$scap_date = Get-Date -UFormat "%Y-%m-%d"
		Start-Process -FilePath "C:\Program Files\SCAP Compliance Checker 5.10.2\cscc" -NoNewWindow -Wait
		Move-Item -Path "C:\Users\$Env:UserName\SCC\Sessions\$scap_date*" -Destination "$Audit_act"
	}
	
	# System audits
	if ($selectedItems -eq "Virus def update" -or $selectedItems -eq "Last quick scan" -or $selectedItems -eq "Last Full scan" -or $selectedItems -eq "Last backup" -or $selectedItems -eq  "Last Update"-or $selectedItems -eq "List software" -or $selectedItems -eq "Backup SEC logs" -or $selectedItems -eq "Backup APP logs" -or $selectedItems -eq "Backup SYS logs") {
		
		# back up logs if needed
		if ($selectedItems -eq "Backup SEC logs" -or $selectedItems -eq "Backup APP logs" -or $selectedItems -eq "Backup SYS logs") {
			
			# create folder for back ups of logs
			$Logs_folder = "$Audit_act\Logs"
			New-Item -ItemType Directory -Force -Path C:$Logs_folder | Out-Null
			
			if ($selectedItems -eq "Backup SEC logs") {
				wevtutil epl Security $Logs_folder\$env:computername'_security_'$timestamp.evtx

			}
			if ($selectedItems -eq "Backup APP logs") {
				wevtutil epl Application $Logs_folder\$env:computername'_application_'$timestamp.evtx

			}
			if ($selectedItems -eq "Backup SYS logs") {
				wevtutil epl System $Logs_folder\$env:computername'_system_'$timestamp.evtx
			}
		}# Log backups
		
		# text report
		if ($selectedItems -eq "Virus def update" -or $selectedItems -eq "Last quick scan" -or $selectedItems -eq "Last Full scan" -or $selectedItems -eq "Last backup" -or $selectedItems -eq "List software") {
			
			#create text file for output
			$System_txt = "$Audit_act\system_info.txt"
			
			# to be removed
			$junk = "[@{}=]"
			
			if ($selectedItems -eq "Virus def update") {
				$virusDef = (Get-MpComputerStatus | Select  'AntiSpywareSignatureLastUpdated') -replace "AntiSpywareSignatureLastUpdated","Virus Signature updated:   "
				$virusDef = [regex]::Replace($virusDef,$junk,"")
				echo $virusDef >> $System_txt
			}
			if ($selectedItems -eq "Last quick scan") {
				$virusScan_q = (Get-MpComputerStatus | Select  'QuickScanEndTime') -replace "QuickScanEndTime", "Last completed quick scan "
				$virusScan_q = [regex]::Replace($virusScan_q,$junk,"")
				echo $virusScan_q >> $System_txt
			}
			if ($selectedItems -eq "Last Full scan") {
				$virusScan_f = (Get-MpComputerStatus | Select  'FullScanEndTime') -replace "FullScanEndTime", "Last completed full scan "
				$virusScan_f = [regex]::Replace($virusScan_f,$junk,"")
				echo $virusScan_f >> $System_txt
			}
			if ($selectedItems -eq "Last backup") {
				$Backup = Get-WinEvent -Maxevents 1 -FilterHashTable @{ logname = 'Application'; id =4098} >> $System_txt
				echo $Backup >> $System_txt
			}
			if ($selectedItems -eq "Last backup") {
				
				$Patch = Get-WinEvent -Maxevents 1 -FilterHashTable @{ logname = 'Setup'; id =2}
				$Patch_mess = $Patch.Message
				$Patch_time = $Patch.TimeCreated
	
				echo "$Patch_mess 	 $Patch_time" >> $System_txt
			}
			if ($selectedItems -eq "List software") {
				wmic product get name,description,version,InstallDate > $Audit_act\"$env:computername.software.txt"
			}
			
		}#text report
	}#System Audits
	
	if ($selectedItems -eq "User List" -or $selectedItems -eq "Failed Logins" -or $selectedItems -eq "Account Changes" -or $selectedItems -eq "Boot/login Report") {
		
		#create output text file as well list of Users
		$Users_txt = "$Audit_act\users_info.txt"
		
		#User table - List if admin, enabled and days since last login (with date)
		if ($selectedItems -eq "User List") {
			
			$userList  = New-Object "System.Collections.Generic.List[System.Object]" #create list object (custom)
			$userList = [System.Collections.ArrayList]@() #fill list with all users on machine
			
			$adminList = @(Get-LocalGroupMember -Name Administrators | Select Name) #create list of all admin on machine
	
			#create list of system objects (users) storing the following variables:
			#	username/ last login (date)/ last login (number of days) / is enabled / is admin
			Get-LocalUser | Select-Object -Property Name,LastLogon,Enabled | foreach {
	
				#updates date/time of users last login
				if ($_.LastLogon -ne $null) {
					$LastLogon_Days = New-TimeSpan -Start $_.LastLogon -End (Get-Date) | Select Days
					$LastLogon_Days = $LastLogon_Days.Days #Convert Sys.Obj to int
				}
				else {
					$LastLogon_Days = "-" # means user has never logged in
				}

				#create object with variables	
				$userObj = [PSCustomObject]@{
					"Name" = $_.Name
					"Last_Logon" = $_.LastLogon
					"LastLogonDays" = $LastLogon_Days
					"Enabled" = $_.Enabled
					"isAdmin" = "" # stays blank if not admin
				}
				$userList.Add($userObj) > $null
			}#Create user obj and add to list

			# Create admin Variable 
			#	cycle through user list
			foreach ( $user in $userList ){
		
				$thisuser = $env:computername +"\"+ $user.Name #current user
	
			#cycle through all admins
				foreach ( $admin in $adminList ) {
			
					$admin = $admin -replace "@{Name=" -replace ""
					$admin = $admin -replace "}" -replace ""
				#if current user is in admin list update object variable
					if ( $admin -eq $thisuser ) {
						$user.isAdmin = "admin"
					}
				}# innner for admins
			} # outer for user

			#header for output
			echo "`nUsername		  Admin 	Enabled    Days Since Last Login/Date`n**********************************************************" >> $Users_txt

			#output for users table
			foreach ( $user in $userList ){
			echo ("{0,-25} {1,-13} {2,-10} {3,-3} {4,-1}" -f $user.Name, $user.isAdmin, $user.Enabled, $user.LastLogonDays,$user.Last_Logon) >> $Users_txt
			}#output user list to txt
		}#User list selection 
		
		
		if ($selectedItems -eq "Failed Logins" ){
			
			Echo "`n`nFAILED LOGINS `n     User (target)    Date/time" >> $Users_txt
			Get-WinEvent -FilterHashTable @{ logname = 'Security'; StartTime=$Aud_date; id =4625} | ForEach-Object {
				$user = $_.properties[5].value
				$time = $_.TimeCreated
				Echo "     $user        $time" >> $Users_txt
			}

			
		}
		
		if ($selectedItems -eq "Account Changes" ) {
			
			echo "`n`nAccount changes`n***********************************************************" >> $Users_txt

			Get-WinEvent -FilterHashTable @{ logname = 'Security'; StartTime=$Aud_date; id =4720,4722,4724,4725,4726,4740,4767} | ForEach-Object {
    
				$id = $_.id
				$time = $_.TimeCreated
	
				$executor_acc = $_.properties[4].value # User who completed task
				$affected_acc = $_.properties[0].value # account task was completed on
	
				if ( $id -eq 4720){
					echo "ACC Created:        '$affected_acc' created by '$executor_acc' -> $time" >> $Users_txt
				}
				if ( $id -eq 4722){
					echo "ACC enabled:        '$affected_acc' enabled by '$executor_acc' -> $time" >> $Users_txt
				}
				if ( $id -eq 4724){
					echo "ACC password reset: '$affected_acc' pw reset by '$executor_acc' -> $time" >> $Users_txt
				}
				if ( $id -eq 4725){
					echo "ACC disabled:       '$affected_acc' disabled by '$executor_acc' -> $time" >> $Users_txt
				}
				if ( $id -eq 4726){
					echo "ACC deleted:        '$affected_acc' deleted by '$executor_acc' -> $time" >> $Users_txt
				}
				if ( $id -eq 4740){
					echo "ACC locked out:     '$affected_acc' locked by '$executor_acc' -> $time" >> $Users_txt
				}
				if ( $id -eq 4767){
					echo "ACC unlocked:       '$affected_acc' unlocked by '$executor_acc' ->	$time" >> $Users_txt
				}
			}
		}# if Account changes
		
		if ($selectedItems -eq "Boot/login Report") {
			
			# output text
			$BootLog = "$Audit_act\Boot+Logins.txt"
	
			echo "Legend:`n" >> $BootLog
			echo "DWM-#  : Desktop Window Manager -> Service that manages " >> $BootLog
			echo "UMFD-# : User Mode Font Driver -> Service management that manages fonts for the User" >> $BootLog
			echo "NETWORK SERVICE : Limited Service account that has a standard privileges" >> $BootLog
			echo "LOCAL SERVICE   : Limited service account that has a limited access to the network" >> $BootLog
			echo "-------------------------------------`n`n" >> $BootLog
		
			echo "$weekDay $curDay End" >> $BootLog
	
			Get-WinEvent -FilterHashTable @{ logname = 'Security','System'; StartTime=$Aud_date; id = 6008,4608,4624,4634,1074,30,107,42} | ForEach-Object {
		
				$id = $_.id
				[string]$timeDay = $_.TimeCreated
				
				$day = $timeDay[0..9] -join ''
				$time = $timeDay[11..18] -join ''
		
				if ($curDay -ne $day) {
					echo "$weekDay $curDay Start" >> $BootLog
					$curDay = $day
					$weekDay = ([datetime]$day).DayOfWeek
					echo "$weekDay $curDay End" >> $BootLog
				}
		
				#login
				if ( $id -eq 4624){
					$acc = $_.properties[5].value
					if ( $acc -ne "SYSTEM"){
					echo "	4624	LOG ON - $acc - $time" >> $BootLog
					}
				}
				#logoff
				if ($id -eq 4634){
					$acc = $_.properties[1].value
					echo "	4634	LOG OFF - $acc - $time" >> $BootLog
				}
				#shutdown/restart
				if ($id -eq 1074){
					$type = $_.properties[4].value
					echo "		1074	$type - $time" >> $BootLog
				}
				#unexpected shutdown
				if ($id -eq 6008){
					$type = $_.properties[4].value
					echo "		6008	$type - $time" >> $BootLog
				}
				#boot up
				if ( $id -eq 30){
					echo "	30 Boot - $time" >> $BootLog
				}
				#Wake from sleep
				if ($id -eq 107){
					echo "	107 Wake - $time" >> $BootLog
				}
				#Sleep
				if ($id -eq 42){
					echo "	42 Sleep - $time" >> $BootLog
				}
				if ( $id -eq 4608){
					echo "	4608 Boot? - $time" >> $BootLog
				}
			}#boot/login audits
	
			echo "$weekDay $curDay Start" >> $BootLog
			
		}#if Boot/Login Report
		
	}#if users 
	
    [System.Windows.Forms.MessageBox]::Show("$Audit_act You selected: " + ($selectedItems -join ", "))
	$Input_GUI.close()
})# Submit button is clicked


#4) Show form --> IMPORTANT DO NOT DELETE!!!!
[void]$Input_GUI.ShowDialog()

#open Audit folder once complete
Invoke-Item C:$Audit_act
