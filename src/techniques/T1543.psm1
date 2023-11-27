function Test-T1543 {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory)]
		[TrawlerState]
		$State
	)

	Test-Services $State
	Test-ServicesByRegex $State
}
function Test-Services {
	[CmdletBinding()]
	param (
		[Parameter()]
		[TrawlerState]
		$State
	)
	# Supports Dynamic Snapshotting
	# Support Drive Retargeting
	$State.WriteMessage("Checking Windows Services")
	$default_service_exe_paths = @(
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /medsvc",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /svc",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft\Edge\Application\*\elevation_service.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /medsvc",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /svc",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe`" /service",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Google\Chrome\Application\*\elevation_service.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Microsoft OneDrive\*\FileSyncHelper.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Microsoft OneDrive\*\OneDriveUpdaterService.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Microsoft Update Health Tools\uhssvc.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe`" -s NVDisplay.ContainerLocalSystem -f `"$($State.DriveTargets.AssumedHomeDrive)\ProgramData\NVIDIA\NVDisplay.ContainerLocalSystem.log`" -l 3 -d `"$($State.DriveTargets.AssumedHomeDrive)\Program Files\NVIDIA Corporation\Display.NvContainer\plugins\LocalSystem`" -r -p 30000 ",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Windows Media Player\wmpnetwk.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\ProgramData\Microsoft\Windows Defender\Platform\*\NisSrv.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Windows\CxSvc\CxAudioSvc.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Windows\CxSvc\CxUtilSvc.exe`"",
		"`"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\wbengine.exe`"",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\Microsoft.Net\*\*\WPF\PresentationFontCache.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\Microsoft.NET\Framework64\*\SMSvcHost.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\servicing\TrustedInstaller.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\AgentService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\alg.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\Alps\GlidePoint\HidMonitorSvc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\AppVClient.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\cAVS\Intel(R) Audio Service\IntelAudioService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\CredentialEnrollmentManager.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\cui_dch.inf_amd64_*\igfxCUIService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_*\HotKeyServiceUWP.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\hpqkbsoftwarecompnent.inf_amd64_*\LanWlanWwanSwitchingServiceUWP.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\iaahcic.inf_amd64_*\RstMwService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\igcc_dch.inf_amd64_*\OneApp.IGCC.WinService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\IntelCpHDCPSvc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\iigd_dch.inf_amd64_*\IntelCpHeciSvc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\fxssvc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\ibtsiva",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\locator.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\lsass.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\msdtc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\msiexec.exe /V",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\nvwmi64.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\OpenSSH\ssh-agent.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\PerceptionSimulation\PerceptionSimulationService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\RSoPProv.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\WINDOWS\RtkBtManServ.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\runSW.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k rpcss"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\SearchIndexer.exe /Embedding",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\SecurityHealthService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\SensorDataService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\SgrmBroker.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\snmptrap.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\spectrum.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\spoolsv.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\sppsvc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k AarSvcGroup -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k appmodel -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k appmodel",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k AppReadiness -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k AppReadiness",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k AssignedAccessManagerSvc",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k autoTimeSvc",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k AxInstSVGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k BcastDVRUserService",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k BthAppGroup -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k Camera",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k CameraMonitor",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k ClipboardSvcGroup -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k CloudIdServiceGroup -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k DcomLaunch -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k DcomLaunch",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k defragsvc",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k DevicesFlow -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k DevicesFlow",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k diagnostics",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k DialogBlockingService",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k GraphicsPerfSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k ICService -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k imgsvc",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k ICService",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k KpsSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k localService -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNoNetwork",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNoNetworkFirewall -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServicePeerNet",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LxssManagerUser -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k McpManagementServiceGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetSvcs -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkServiceNetworkRestricted -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkServiceNetworkRestricted",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k PeerDist",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k print",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k PrintWorkflow",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k rdxgroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k rpcss -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k RPCSS -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k SDRSVC",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k smbsvcs",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k smphost",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k swprv",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k termsvcs",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k UdkSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k UnistackSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k utcsvc -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k utcsvc",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k WbioSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k WepHostSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k WerSvcGroup",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k wsappx -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k wcssvc"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k wsappx",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k wusvcs -p",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\TieringEngineService.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\UI0Detect.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\vds.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\vssvc.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\wbem\WmiApSrv.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\SysWow64\perfhost.exe",
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\SysWOW64\XtuService.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\WINDOWS\system32\dllhost.exe /Processid:*"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\1394ohci.sys"
		"System32\drivers\3ware.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k AarSvcGroup -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k AarSvcGroup -p"
		"System32\drivers\ACPI.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\AcpiDev.sys"
		"System32\Drivers\acpiex.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\acpipagr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\acpipmi.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\acpitime.sys"
		"system32\drivers\Acx01000.sys"
		"System32\drivers\ADP80XX.SYS"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\afd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\afunix.sys"
		"system32\DRIVERS\ahcache.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\alg.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\amdgpio2.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\amdi2c.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\amdk8.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\amdppm.sys"
		"System32\drivers\amdsata.sys"
		"System32\drivers\amdsbs.sys"
		"System32\drivers\amdxata.sys"
		"system32\drivers\appid.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\AppleKmdfFilter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\AppleLowerFilter.sys"
		"system32\drivers\applockerfltr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k AppReadiness -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\AppVClient.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\AppvStrm.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\AppvVemgr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\AppvVfs.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k wsappx -p"
		"System32\drivers\arcsas.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\ASUS\ARMOURY CRATE Lite Service\ArmouryCrate.Service.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\ASUS\AXSP\*\atkexComSvc.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k AssignedAccessManagerSvc"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\ASUS\Update\AsusUpdate.exe`" /svc"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\ASUS\AsusCertService\AsusCertService.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\ASUS\AsusFanControlService\*\AsusFanControlService.exe`""
		"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\AsIO2.sys"
		"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\AsIO3.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\ASUS\Update\AsusUpdate.exe`" /medsvc"
		#"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\AsusUpdateCheck.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\asyncmac.sys"
		"System32\drivers\atapi.sys"
		#"\??\D:\SteamLibrary\steamapps\common\Call of Duty HQ\randgrid.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k autoTimeSvc"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k AxInstSVGroup"
		"System32\drivers\bxvbda.sys"
		"system32\drivers\bam.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\basicdisplay.inf_amd64_*\BasicDisplay.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\basicrender.inf_amd64_*\BasicRender.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k BcastDVRUserService"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k BcastDVRUserService"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\bcmfn2.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Common Files\BattlEye\BEService.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\bindflt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k BthAppGroup -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k BthAppGroup -p"
		"system32\DRIVERS\bowser.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\BthA2dp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\BthEnum.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\bthhfenum.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\Microsoft.Bluetooth.Legacy.LEEnumerator.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\BTHMINI.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\bthmodem.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\bthpan.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\BTHport.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\BTHUSB.sys"
		"System32\drivers\bttflt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\buttonconverter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\CAD.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k appmodel -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k ClipboardSvcGroup -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k ClipboardSvcGroup -p"
		"system32\DRIVERS\cdfs.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\cdrom.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs"
		"System32\drivers\cht4sx64.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\cht4vx64.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\circlass.sys"
		"system32\drivers\cldflt.sys"
		"System32\drivers\CLFS.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe`" /service"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k wsappx -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k CloudIdServiceGroup -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\CmBatt.sys"
		"System32\Drivers\cng.sys"
		"System32\DRIVERS\cnghwassist.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Docker\Docker\com.docker.service`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\compositebus.inf_amd64_*\CompositeBus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\dllhost.exe /Processid:{*}"
		"System32\drivers\condrv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p"
		#"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\CorsairGamingAudioCfgService64.exe"
		#"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\CorsairGamingAudio64.sys"
		#"\??\$($State.DriveTargets.AssumedHomeDrive)\Program Files\Corsair\CORSAIR iCUE 4 Software\CorsairLLAccess64.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Corsair\CORSAIR iCUE 4 Software\CueLLAccessService.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Corsair\CORSAIR iCUE 4 Software\Corsair.Service.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Corsair\CORSAIR iCUE 4 Software\CueUniwillService.exe`""
		#"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\CorsairVBusDriver.sys"
		#"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\CorsairVHidDriver.sys"
		#"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\temp\cpuz152\cpuz152_x64.sys"
		#"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\temp\cpuz153\cpuz153_x64.sys"
		#"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\temp\cpuz154\cpuz154_x64.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\CredentialEnrollmentManager.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\CredentialEnrollmentManager.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k NetworkService -p"
		"system32\drivers\csc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\CtiAIo64.sys"
		"system32\drivers\dam.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe`" /svc"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe`" /medsvc"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DbxSvc.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\dc1-controller.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k defragsvc"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DevicesFlow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\Drivers\dfsc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DiagSvcs\DiagnosticsHub.StandardCollector.Service.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k diagnostics"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k utcsvc -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DialogBlockingService"
		"System32\drivers\disk.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\dmvsc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\drmkaud.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\dxgkrnl.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\e2f68.inf_amd64_*\e2f68.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\EasyAntiCheat\EasyAntiCheat.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe`""
		"System32\drivers\evbda.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /svc"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`" /medsvc"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\lsass.exe"
		"System32\drivers\EhStorClass.sys"
		"System32\drivers\EhStorTcgDrv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k appmodel -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\errdev.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\fxssvc.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\fdc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\drivers\filecrypt.sys"
		"System32\drivers\fileinfo.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Microsoft OneDrive\*\FileSyncHelper.exe`""
		"system32\drivers\filetrace.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\flpydisk.sys"
		"system32\drivers\fltmgr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\Microsoft.Net\Framework64\v*\WPF\PresentationFontCache.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k Camera"
		"System32\drivers\FsDepends.sys"
		"System32\DRIVERS\fvevol.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\NVIDIA Corporation\FrameViewSDK\nvfvsdksvc_x64.exe`" -service"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\ASUS\GameSDK Service\GameSDK.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vmgencounter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\genericusbfn.inf_amd64_*\genericusbfn.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Google\Chrome\Application\*\elevation_service.exe`""
		#"system32\DRIVERS\googledrive*.sys"
		"System32\Drivers\msgpioclx.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"System32\drivers\gpuenergydrv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k GraphicsPerfSvcGroup"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /svc"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Google\Update\GoogleUpdate.exe`" /medsvc"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\hcmon.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\HdAudio.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\HDAudBus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\HidBatt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hidbth.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hidi2c.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hidinterrupt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hidir.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hidspi.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hidusb.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k NetSvcs -p"
		"System32\drivers\hnswfpdriver.sys"
		"System32\drivers\HpSAMD.sys"
		"system32\drivers\HTTP.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hvcrash.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\drivers\hvservice.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\hvsocketcontrol.sys"
		"System32\Drivers\mshwnclx.sys"
		"System32\drivers\hwpolicy.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\hyperkbd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\HyperVideo.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\i8042prt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iagpio.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iai2c.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_GPIO2.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_GPIO2_BXT_P.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_GPIO2_CNL.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_GPIO2_GLK.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_I2C.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_I2C_BXT_P.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_I2C_CNL.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSS2i_I2C_GLK.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSSi_GPIO.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\iaLPSSi_I2C.sys"
		"System32\drivers\iaStorAVC.sys"
		"System32\drivers\iaStorV.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\ibbus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\ibtusb.inf_amd64_f75065d93521b024\ibtusb.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Corsair\CORSAIR iCUE 4 Software\iCUEDevicePluginHost.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\IndirectKmd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"System32\drivers\intelide.sys"
		"System32\drivers\intelpep.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\intelpmax.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\intelppm.sys"
		"system32\drivers\iorate.sys"
		"system32\DRIVERS\ipfltdrv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetSvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\IPMIDrv.sys"
		"System32\drivers\ipnat.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\ipt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\drivers\isapnp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\msiscsi.sys"
		"System32\drivers\ItSas35i.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\JetBrains\ETW Host\16\JetBrains.Etw.Collector.Host.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\dal.inf_*\jhi_service.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\kbdclass.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\kbdhid.sys"
		"system32\drivers\kbldfltr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\kdnic.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\lsass.exe"
		"System32\Drivers\ksecdd.sys"
		"System32\Drivers\ksecpkg.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\ksthunk.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation -p"
		"System32\drivers\l2bridge.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\LGHUB\lghub_updater.exe`" --run-as-service"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService -p"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\LightingService\LightingService.exe`""
		"system32\drivers\lltdio.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\logi_generic_hid_filter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\logi_joy_bus_enum.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\logi_joy_hid_filter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\logi_joy_hid_lo.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\logi_joy_vir_hid.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\logi_joy_xlcore.sys"
		"System32\drivers\lsi_sas.sys"
		"System32\drivers\lsi_sas2i.sys"
		"System32\drivers\lsi_sas3i.sys"
		"System32\drivers\lsi_sss.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\luafv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs"
		"system32\drivers\lxss.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LxssManagerUser -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LxssManagerUser -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mausbhost.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mausbip.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\Drivers\MbamChameleon.sys"
		"system32\DRIVERS\MbamElam.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Malwarebytes\Anti-Malware\MBAMService.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\Drivers\mbamswissarmy.sys"
		"system32\drivers\MbbCx.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k McpManagementServiceGroup"
		"System32\drivers\megasas.sys"
		"System32\drivers\MegaSas2i.sys"
		"System32\drivers\megasas35i.sys"
		"System32\drivers\megasr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\heci.inf_amd64_*\x64\TeeDriverW10x64.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft\Edge\Application\*\elevation_service.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\Microsoft.Bluetooth.AvrcpTransport.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mlx4_bus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\mmcss.sys"
		"system32\drivers\modem.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\MongoDB\Server\*\bin\mongod.exe`" --config `"$($State.DriveTargets.AssumedHomeDrive)\Program Files\MongoDB\Server\*\bin\mongod.cfg`" --service"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\monitor.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mouclass.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mouhid.sys"
		"System32\drivers\mountmgr.sys"
		"\??\$($State.DriveTargets.AssumedHomeDrive)\ProgramData\Microsoft\Windows Defender\Definition Updates\{*}\MpKslDrv.sys"
		"System32\drivers\mpsdrv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\mrxdav.sys"
		"system32\DRIVERS\mrxsmb.sys"
		"system32\DRIVERS\mrxsmb20.sys"
		"System32\drivers\bridge.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\msdtc.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\msgpiowin32.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mshidkmdf.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mshidumdf.sys"
		"\??\$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\MsIo64.sys"
		"System32\drivers\msisadrv.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\msiexec.exe /V"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\MSKSSRV.sys"
		"system32\drivers\mslldp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\MSPCLOCK.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\MSPQM.sys"
		"system32\drivers\msquic.sys"
		"system32\drivers\msseccore.sys"
		"system32\drivers\mssecflt.sys"
		"system32\drivers\mssecwfp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\mssmbios.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\MSTEE.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\MTConfig.sys"
		"System32\Drivers\mup.sys"
		"System32\drivers\mvumis.sys"
		"system32\DRIVERS\nwifi.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetSvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\ndfltr.sys"
		"system32\drivers\ndis.sys"
		"System32\drivers\ndiscap.sys"
		"System32\drivers\NdisImPlatform.sys"
		"System32\DRIVERS\ndistapi.sys"
		"system32\drivers\ndisuio.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\NdisVirtualBus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\ndiswan.sys"
		"System32\DRIVERS\ndiswan.sys"
		"system32\drivers\NDKPing.sys"
		"System32\DRIVERS\NDProxy.sys"
		"system32\drivers\Ndu.sys"
		"system32\drivers\NetAdapterCx.sys"
		"system32\drivers\netbios.sys"
		"System32\DRIVERS\netbt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\lsass.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\Microsoft.NET\Framework64\v*\SMSvcHost.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\netvsc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\Netwtw10.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\Netwtw12.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\npcap.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\npsvctrig.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"system32\drivers\nsiproxy.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k NetSvcs"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe`" -s NvContainerLocalSystem -f `"$($State.DriveTargets.AssumedHomeDrive)\ProgramData\NVIDIA\NvContainerLocalSystem.log`" -l 3 -d `"$($State.DriveTargets.AssumedHomeDrive)\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem`" -r -p 30000 -st `"$($State.DriveTargets.AssumedHomeDrive)\Program Files\NVIDIA Corporation\NvContainer\NvContainerTelemetryApi.dll`""
		"System32\drivers\nvdimm.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_*\Display.NvContainer\NVDisplay.Container.exe -s NVDisplay.ContainerLocalSystem -f $($State.DriveTargets.AssumedHomeDrive)\ProgramData\NVIDIA\NVDisplay.ContainerLocalSystem.log -l 3 -d $($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_*\Display.NvContainer\plugins\LocalSystem -r -p 30000 -cfg NVDisplay.ContainerLocalSystem\LocalSystem"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\nvhda64v.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_*\nvlddmkm.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\nvmoduletracker.inf_amd64_*\NvModuleTracker.sys"
		"System32\drivers\nvraid.sys"
		"System32\drivers\nvstor.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\nvvad64v.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\nvvhci.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Microsoft OneDrive\*\OneDriveUpdaterService.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"System32\drivers\p9rdr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\parport.sys"
		"System32\drivers\partmgr.sys"
		"system32\drivers\passthruparser.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\drivers\pci.sys"
		"System32\drivers\pciide.sys"
		"System32\drivers\pcmcia.sys"
		"System32\drivers\pcw.sys"
		"system32\drivers\pdc.sys"
		"system32\drivers\peauth.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k PeerDist"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\PerceptionSimulation\PerceptionSimulationService.exe"
		"System32\drivers\percsas2i.sys"
		"System32\drivers\percsas3i.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\SysWow64\perfhost.exe"
		#"$($State.DriveTargets.AssumedHomeDrive)`\Program Files (x86)\PgBouncer\bin\pgbouncer.exe --service `"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\PgBouncer\share\pgbouncer.ini`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"system32\drivers\PktMon.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p"
		#"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\GeoComply\//PlayerLocationCheck///Application/service.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"System32\drivers\pmem.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\pnpmem.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServicePeerNet"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\portcfg.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\PostgreSQL\14\bin\pg_ctl.exe`" runservice -N `"postgresql-x64-14`" -D `"$($State.DriveTargets.AssumedHomeDrive)\Program Files\PostgreSQL\14\data`" -w"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\raspptp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k print"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k PrintWorkflow"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k PrintWorkflow"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Private Internet Access\pia-service.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Private Internet Access\pia-wgservice.exe`" `"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Private Internet Access\data\wgpia0.conf`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\processr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"System32\drivers\pacer.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"system32\drivers\pvhdparser.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\qwavedrv.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\erl-*\erts-*\bin\erlsrv.exe`""
		"system32\DRIVERS\ramdisk.sys"
		"System32\DRIVERS\rasacd.sys"
		#"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\AgileVpn.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\rasl2tp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs"
		"System32\DRIVERS\raspppoe.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\rassstp.sys"
		"system32\DRIVERS\rdbss.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\rdpbus.sys"
		"System32\drivers\rdpdr.sys"
		"System32\drivers\rdpvideominiport.sys"
		"System32\drivers\rdyboost.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k localService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k rdxgroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\rfcomm.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\rhproxy.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Rockstar Games\Launcher\RockstarService.exe`""
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\ASUS\ROG Live Service\ROGLiveService.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k RPCSS -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\locator.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k rpcss -p"
		"system32\drivers\rspndr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vms3cap.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\lsass.exe"
		"System32\drivers\sbp2port.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted"
		"System32\DRIVERS\scfilter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"System32\drivers\scmbus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\sdbus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\SDFRd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k SDRSVC"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\sdstor.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\SecurityHealthService.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\SensorDataService.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"system32\drivers\SerCx.sys"
		"system32\drivers\SerCx2.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\serenum.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\serial.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\sermouse.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\sfloppy.sys"
		"system32\drivers\SgrmAgent.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\SgrmBroker.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"System32\drivers\SiSRaid2.sys"
		"System32\drivers\sisraid4.sys"
		"System32\drivers\SmartSAMD.sys"
		"System32\DRIVERS\smbdirect.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k smphost"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\snmptrap.exe"
		"system32\drivers\spaceparser.sys"
		"System32\drivers\spaceport.sys"
		"System32\drivers\SpatialGraphFilter.sys"
		"system32\drivers\SpbCx.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\spectrum.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\spoolsv.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\sppsvc.exe"
		"System32\DRIVERS\srv2.sys"
		"System32\DRIVERS\srvnet.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\OpenSSH\ssh-agent.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k appmodel -p"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Common Files\Steam\steamservice.exe`" /RunAsService"
		"System32\drivers\stexstor.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k imgsvc"
		"System32\drivers\storahci.sys"
		"System32\drivers\vmstorfl.sys"
		"System32\drivers\stornvme.sys"
		"system32\drivers\storqosflt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"System32\drivers\storufs.sys"
		"System32\drivers\storvsc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\storvsp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\swenum.inf_amd64_*\swenum.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k swprv"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\Synth3dVsc.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k DcomLaunch -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\tap-pia-*.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p"
		"System32\drivers\tcpip.sys"
		"System32\drivers\tcpip.sys"
		"System32\drivers\tcpipreg.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\tdx.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\TeamViewer\TeamViewer_Service.exe`""
		"System32\drivers\IntelTA.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\terminpt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService"
		"$($State.DriveTargets.AssumedHomeDrive)\Program Files\A Subfolder\B Subfolder\C Subfolder\SomeExecutable.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\TieringEngineService.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\tpm.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\servicing\TrustedInstaller.exe"
		"system32\drivers\tsusbflt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\TsUsbGD.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\tsusbhub.sys"
		"System32\drivers\tunnel.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\uaspstor.sys"
		"System32\Drivers\UcmCx.sys"
		"System32\Drivers\UcmTcpciCx.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\UcmUcsiAcpiClient.sys"
		"System32\Drivers\UcmUcsiCx.sys"
		"system32\drivers\ucx01000.sys"
		"system32\drivers\udecx.sys"
		"system32\DRIVERS\udfs.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UdkSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UdkSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\uefi.inf_amd64_*\UEFI.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\UevAgentDriver.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\AgentService.exe"
		"system32\drivers\ufx01000.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\ufxchipidea.inf_amd64_*\UfxChipidea.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\ufxsynopsys.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Microsoft Update Health Tools\uhssvc.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\umbus.inf_amd64_*\umbus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\umpass.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\urschipidea.inf_amd64_*\urschipidea.sys"
		"system32\drivers\urscx01000.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\urssynopsys.inf_amd64_*\urssynopsys.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\usbaudio.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbaudio2.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbccgp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbcir.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbehci.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbhub.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\UsbHub3.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbohci.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbprint.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usb80236.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbser.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\USBSTOR.SYS"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\usbuhci.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\Drivers\usbvideo.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\USBXHCI.SYS"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\lsass.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\VBoxNetAdp6.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\VBoxNetLwf.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Oracle\VirtualBox\VBoxSDS.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\VBoxSup.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\VBoxUSBMon.sys"
		"System32\drivers\vdrvroot.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\vds.exe"
		"System32\drivers\VerifierExt.sys"
		"system32\drivers\vfpext.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vhdmp.sys"
		"system32\drivers\vhdparser.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vhf.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\Vid.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\vrd.inf_amd64_*\vrd.sys"
		#"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\VMware\VMware Workstation\vmware-authd.exe`""
		"System32\drivers\vmbus.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\VMBusHID.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vmbusr.sys"
		"System32\drivers\vmci.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\vmcompute.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vmgid.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k ICService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k ICService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\vmnetadapter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\vmnetbridge.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\SysWOW64\vmnetdhcp.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\vmnetuserif.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vmswitch.sys"
		"system32\drivers\VmsProxyHNic.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\VmsProxyHNic.sys"
		"System32\drivers\vmswitch.sys"
		"system32\drivers\VmsProxy.sys"
		"System32\drivers\vmswitch.sys"
		"System32\drivers\vmswitch.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vmusb.sys"
		# "`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Common Files\VMware\USB\vmware-usbarbitrator64.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\SysWOW64\vmnat.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\vmx86.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\mvvad.sys"
		"System32\drivers\volmgr.sys"
		"System32\drivers\volmgrx.sys"
		"System32\drivers\volsnap.sys"
		"System32\drivers\volume.sys"
		"System32\drivers\vpci.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vpcivsp.sys"
		"System32\drivers\vsmraid.sys"
		"system32\DRIVERS\vsock.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\vssvc.exe"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files (x86)\Microsoft Visual Studio\Shared\Common\DiagnosticsHub.Collection.Service\StandardCollector.Service.exe`""
		"SysWOW64\drivers\vstor2-x64.sys"
		"System32\drivers\vstxraid.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vwifibus.sys"
		"System32\drivers\vwififlt.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\vwifimp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k wusvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\wacompen.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k appmodel -p"
		"System32\DRIVERS\wanarp.sys"
		"System32\DRIVERS\wanarp.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\wbengine.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k WbioSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\wcifs.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\wcnfs.sys"
		"system32\drivers\wd\WdBoot.sys"
		"system32\drivers\Wdf01000.sys"
		"system32\drivers\wd\WdFilter.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\DRIVERS\wdiwifi.sys"
		"system32\drivers\WdmCompanionFilter.sys"
		"system32\drivers\wd\WdNisDrv.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\ProgramData\Microsoft\Windows Defender\Platform\*\NisSrv.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k WepHostSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k WerSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"System32\drivers\wfplwfs.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"system32\drivers\wimmount.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe`""
		"system32\drivers\WindowsTrustedRT.sys"
		"System32\drivers\WindowsTrustedRTProxy.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\winmad.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"system32\drivers\winnat.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k NetworkService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\WinUSB.SYS"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\winverbs.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\wmiacpi.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\wbem\WmiApSrv.exe"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\DriverStore\FileRepository\mewmiprov.inf_amd64_*\WMIRegistrationService.exe"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Windows Media Player\wmpnetwk.exe`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalService -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalService"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted"
		"System32\drivers\WpdUpFltr.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k UnistackSvcGroup"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\drivers\ws2ifsl.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\SearchIndexer.exe /Embedding"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"system32\drivers\WudfPf.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\WUDFRd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\WUDFRd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\DRIVERS\WUDFRd.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\xboxgip.sys"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\system32\svchost.exe -k netsvcs -p"
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\drivers\xinputhid.sys"
		"`"$($State.DriveTargets.AssumedHomeDrive)\Program Files\Common Files\Microsoft Shared\Windows Live\WLIDSVC.EXE`""
		"$($State.DriveTargets.AssumedHomeDrive)\Windows\System32\svchost.exe -k secsvcs"
		"system32\DRIVERS\wfplwf.sys"
		"C:\Windows\system32\drivers\wd.sys"
		"C:\Windows\system32\Wat\WatAdminSvc.exe"
		"system32\DRIVERS\vwifibus.sys"
		"C:\Windows\system32\drivers\vsmraid.sys"
		"C:\Windows\system32\drivers\vmbus.sys"
		"C:\Windows\system32\drivers\viaide.sys"
		"system32\DRIVERS\vhdmp.sys"
		"System32\drivers\rdvgkmd.sys"
		"C:\Windows\System32\drivers\vga.sys"
		"system32\DRIVERS\vgapnp.sys"
		"system32\DRIVERS\usbuhci.sys"
		"system32\DRIVERS\USBSTOR.SYS"
		"system32\DRIVERS\usbhub.sys"
		"system32\DRIVERS\usbehci.sys"
		"system32\DRIVERS\umbus.sys"
		"C:\Windows\system32\drivers\uliagpkx.sys"
		"C:\Windows\system32\drivers\uagp35.sys"
		"system32\drivers\tsusbhub.sys"
		"System32\drivers\truecrypt.sys"
		"System32\DRIVERS\tssecsrv.sys"
		"system32\drivers\tpm.sys"
		"system32\DRIVERS\termdd.sys"
		"system32\DRIVERS\tdx.sys"
		"system32\drivers\tdtcp.sys"
		"system32\drivers\tdpipe.sys"
		"System32\drivers\synth3dvsc.sys"
		"system32\DRIVERS\swenum.sys"
		"C:\Windows\system32\drivers\storvsc.sys"
		"C:\Windows\system32\drivers\stexstor.sys"
		"System32\DRIVERS\srv.sys"
		"system32\DRIVERS\smb.sys"
		"C:\Windows\system32\drivers\sisraid4.sys"
		"C:\Windows\system32\drivers\SiSRaid2.sys"
		"C:\Windows\system32\drivers\sffp_sd.sys"
		"C:\Windows\system32\drivers\sffp_mmc.sys"
		"C:\Windows\system32\drivers\sbp2port.sys"
		"C:\Windows\system32\svchost.exe -k regsvc"
		"system32\drivers\rdprefmp.sys"
		"system32\drivers\rdpencdd.sys"
		"System32\DRIVERS\RDPCDD.sys"
		"system32\DRIVERS\rdpbus.sys"
		"system32\DRIVERS\rassstp.sys"
		"system32\DRIVERS\rasl2tp.sys"
		"C:\Windows\system32\drivers\ql40xx.sys"
		"C:\Windows\system32\drivers\ql2300.sys"
		"system32\DRIVERS\raspptp.sys"
		"C:\Windows\system32\drivers\pciide.sys"
		"C:\Windows\system32\drivers\ohci1394.sys"
		"C:\Windows\system32\drivers\nv_agp.sys"
		"C:\Windows\system32\drivers\nvstor.sys"
		"C:\Windows\system32\drivers\nvraid.sys"
		"`"c:\Program Files\Microsoft Security Client\NisSrv.exe`""
		"`"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe`" -NetMsmqActivator"
		"system32\drivers\MSTEE.sys"
		"system32\DRIVERS\mssmbios.sys"
		"system32\drivers\MSPQM.sys"
		"system32\drivers\MSPCLOCK.sys"
		"`"c:\Program Files\Microsoft Security Client\MsMpEng.exe`""
		"system32\drivers\MSKSSRV.sys"
		"C:\Windows\system32\drivers\msdsm.sys"
		"system32\drivers\msahci.sys"
		"system32\DRIVERS\mrxsmb10.sys"
		"C:\Windows\system32\drivers\mpio.sys"
		"system32\DRIVERS\MpFilter.sys"
		"system32\DRIVERS\mouclass.sys"
		"system32\DRIVERS\monitor.sys"
		"system32\DRIVERS\WUDFRd.sys"
		"C:\Windows\system32\drivers\sffdisk.sys"
		"system32\DRIVERS\NisDrvWFP.sys"
		"C:\Windows\system32\drivers\nfrd960.sys"
		"C:\Windows\system32\drivers\lsi_*.sys"
		"system32\DRIVERS\kbdclass.sys"
		"C:\Windows\system32\drivers\isapnp.sys"
		"system32\drivers\irenum.sys"
		"system32\DRIVERS\intelppm.sys"
		"C:\Windows\system32\drivers\iirsp.sys"
		"`"C:\Windows\Microsoft.NET\Framework64\v3.0\Windows Communication Foundation\infocard.exe`""
		"C:\Windows\system32\drivers\iaStorV.sys"
		"system32\DRIVERS\i8042prt.sys"
		"C:\Windows\system32\drivers\HpSAMD.sys"
		"system32\DRIVERS\HDAudBus.sys"
		"system32\drivers\HdAudio.sys"
		"C:\Windows\system32\drivers\hcw85cir.sys"
		"C:\Windows\system32\drivers\gagp30kx.sys"
		"C:\Windows\system32\drivers\elxstor.sys"
		"C:\Windows\ehome\ehsched.exe"
		"C:\Windows\ehome\ehRecvr.exe"
		"C:\Windows\system32\drivers\evbda.sys"
		"system32\DRIVERS\e1e6032e.sys"
		"System32\drivers\discache.sys"
		"C:\Windows\system32\drivers\crcdisk.sys"
		"system32\DRIVERS\CompositeBus.sys"
		"system32\DRIVERS\compbatt.sys"
		"C:\Windows\system32\drivers\cmdide.sys"
		"system32\DRIVERS\CmBatt.sys"
		"C:\Windows\Microsoft.NET\Framework64\v*\mscorsvw.exe"
		"System32\CLFS.sys"
		"system32\DRIVERS\cdrom.sys"
		"C:\Windows\system32\svchost.exe -k bthsvcs"
		"C:\Windows\System32\Drivers\BrUsbSer.sys"
		"C:\Windows\System32\Drivers\BrUsbMdm.sys"
		"C:\Windows\System32\Drivers\BrUsbWdm.sys"
		"C:\Windows\System32\Drivers\Brserid.sys"
		"C:\Windows\System32\Drivers\BrFiltUp.sys"
		"C:\Windows\System32\Drivers\BrFiltLo.sys"
		"system32\DRIVERS\blbdrive.sys"
		"system32\DRIVERS\b57nd60a.sys"
		"C:\Windows\system32\drivers\bxvbda.sys"
		"system32\DRIVERS\athrx.sys"
		"system32\DRIVERS\asyncmac.sys"
		"C:\Windows\Microsoft.NET\Framework64\v*\aspnet_state.exe"
		"C:\Windows\system32\drivers\arcsas.sys"
		"C:\Windows\system32\drivers\arc.sys"
		"C:\Windows\system32\drivers\appid.sys"
		"C:\Windows\system32\IEEtwCollector.exe*"
		"C:\Windows\Microsoft.NET\Framework\v*\mscorsvw.exe"
		"C:\Windows\System32\Drivers\BrSerWdm.sys"
		"C:\Windows\system32\drivers\amdsbs.sys"
		"C:\Windows\system32\drivers\amdsata.sys"
		"C:\Windows\system32\drivers\amdide.sys"
		"C:\Windows\system32\drivers\aliide.sys"
		"C:\Windows\system32\drivers\agp440.sys"
		"C:\Windows\system32\drivers\adpu320.sys"
		"C:\Windows\system32\drivers\adpahci.sys"
		"C:\Windows\system32\drivers\adp94xx.sys"
	)


	#$services = Get-CimInstance -ClassName Win32_Service  | Select-Object Name, PathName, StartMode, Caption, DisplayName, InstallDate, ProcessId, State
	$service_path = "$($State.DriveTargets.Hklm)SYSTEM\$($State.DriveTargets.CurrentControlSet)\Services"
	$service_list = New-Object -TypeName "System.Collections.ArrayList"
	if (Test-Path -Path "Registry::$service_path") {
		$items = Get-ChildItem -Path "Registry::$service_path" | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($item in $items) {
			$path = "Registry::" + $item.Name
			$data = Get-ItemProperty -Path $path | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSProvider
			if ($data.ImagePath) {
				$service = [PSCustomObject]@{
					Name     = $data.PSChildName
					PathName = $data.ImagePath
				}
				$service.PathName = $service.PathName.Replace("\SystemRoot", "$($State.DriveTargets.AssumedHomeDrive)\Windows")
				$service_list.Add($service) | Out-Null
			}
		}
	}
	foreach ($service in $service_list) {
		if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($service.Name, $service.PathName, "Services"), $true)) {
			continue
		}

		foreach ($term in $rat_terms) {
			if ($service.PathName -match ".*$term.*") {
				# Service has a suspicious launch pattern matching a known RAT
				$detection = [PSCustomObject]@{
					Name      = 'Service Argument has known-RAT Keyword'
					Risk      = [TrawlerRiskPriority]::Medium
					Source    = 'Services'
					Technique = "T1543.003: Create or Modify System Process: Windows Service"
					Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName + ", RAT Keyword: " + $term
				}
				$State.WriteDetection($detection)
			}
		}
		if ($service.PathName -match "$($State.DriveTargets.AssumedHomeDrive)\\Windows\\Temp\\.*") {
			# Service launching from Windows\Temp
			$detection = [PSCustomObject]@{
				Name      = 'Service Launching from Windows Temp Directory'
				Risk      = [TrawlerRiskPriority]::High
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			$State.WriteDetection($detection)
		}
		# Detection - Non-Standard Tasks
		foreach ($i in $default_service_exe_paths) {
			if ( $service.PathName -like $i) {
				$exe_match = $true
				break
			}
			elseif ($service.PathName.Length -gt 0) {
				$exe_match = $false
			}
		}
		if ($exe_match -eq $false) {
			# Current Task Executable Path is non-standard
			$detection = [PSCustomObject]@{
				Name      = 'Non-Standard Service Path'
				Risk      = [TrawlerRiskPriority]::Low
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			$State.WriteDetection($detection)
		}
		if ($service.PathName -match ".*cmd.exe /(k|c).*") {
			# Service has a suspicious launch pattern
			$detection = [PSCustomObject]@{
				Name      = 'Service launching from cmd.exe'
				Risk      = [TrawlerRiskPriority]::Medium
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			$State.WriteDetection($detection)
		}
		if ($service.PathName -match ".*powershell.exe.*") {
			# Service has a suspicious launch pattern
			$detection = [PSCustomObject]@{
				Name      = 'Service launching from powershell.exe'
				Risk      = [TrawlerRiskPriority]::Medium
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			$State.WriteDetection($detection)
		}

		if ($service.PathName -match $suspicious_terms) {
			# Service has a suspicious launch pattern
			$detection = [PSCustomObject]@{
				Name      = 'Service launching with suspicious keywords'
				Risk      = [TrawlerRiskPriority]::High
				Source    = 'Services'
				Technique = "T1543.003: Create or Modify System Process: Windows Service"
				Meta      = "Service Name: " + $service.Name + ", Service Path: " + $service.PathName
			}
			$State.WriteDetection($detection)
		}
	}
}

function Test-ServicesByRegex {
	# TODO - Check FailureCommand for abnormal entries
	# Supports Drive Retargeting
	# Support Dynamic Snapshotting
	$State.WriteMessage("Checking Service Registry Entries")
	# Service DLL Inspection

	$path = "{0}SYSTEM\$($State.DriveTargets.CurrentControlSet)\Services" -f $regtarget_hklm
	if (Test-Path -Path "Registry::$path") {
		$services = Get-ChildItem -Path "Registry::$path" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSProvider
		foreach ($service in $services) {
			Get-TrawlerItemData -Path $service.Name -ItemType ItemProperty -AsRegistry | ForEach-Object {
				if ($_.Name -eq 'ImagePath') {
					if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($service.Name, $_.Value, 'Services_REG'), $true)) {
						continue
					}

					if ($image_path_lookup.ContainsKey($service.Name)) {
						if ($_.Value -notmatch $image_path_lookup[$service.Name]) {
							$detection = [PSCustomObject]@{
								Name      = 'Possible Service Hijack - Unexpected ImagePath Location'
								Risk      = [TrawlerRiskPriority]::Medium
								Source    = 'Services'
								Technique = "T1543.003: Create or Modify System Process: Windows Service"
								Meta      = "Key: " + $service.Name + ", Value: " + $_.Value + ", Regex Expected Location: " + $image_path_lookup[$service.Name]
							}
							$State.WriteDetection($detection)
						}
					}
					elseif (1 -eq 1) {
					}
				}
			}
			foreach ($child_key in Get-TrawlerChildItem -Path $service.Name -AsRegistry) {
				Get-TrawlerItemData -Path $child_key.Name -ItemType ItemProperty -AsRegistry | ForEach-Object {
					if ($_.Name -eq "ServiceDll") {
						if ($State.IsExemptBySnapShot([TrawlerSnapShotData]::new($child_key.Name, $_.Value, 'Services_REG'), $true)) {
							continue
						}

						if ($service_dll_lookup.ContainsKey($child_key.Name)) {
							if ($_.Value -notmatch $service_dll_lookup[$child_key.Name]) {
								$detection = [PSCustomObject]@{
									Name      = 'Possible Service Hijack - Unexpected ServiceDll Location'
									Risk      = [TrawlerRiskPriority]::Medium
									Source    = 'Services'
									Technique = "T1543.003: Create or Modify System Process: Windows Service"
									Meta      = "Key: " + $child_key.Name + ", Value: " + $_.Value + ", Regex Expected Location: " + $service_dll_lookup[$child_key.Name]
								}
								$State.WriteDetection($detection)
							}
						}
						elseif (1 -eq 1) {
						}
					}
				}
			}
		}
	}
}