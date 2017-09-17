$EFIDriveLetter  = (GWMI win32_LogicalDisk |? VolumeName -like EFI).DeviceId
$BootDriveLetter = (GWMI win32_LogicalDisk |? VolumeName -like Boot).DeviceId

$BCDPath = $BootDriveLetter + "\Windows\System32\bcdboot.exe"

cmd /c $BCDPath C:\Windows /S $EFIDriveLetter /F UEFI