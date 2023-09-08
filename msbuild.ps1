# Wrapper script for MSBuild
param(
	[string]$SolutionDir = "vs2019",
	[string]$ConfigurationBase = "Windows 10",
	[Parameter(Mandatory = $true)]
	[string]$Arch,
	[Parameter(Mandatory = $true)]
	[string]$Type,
	[string]$SolutionName = "xenvbd",
	[string[]]$ProjectNames = @("xencrsh", "xendisk", "xenvbd")
)

# Function to run MSBuild with specified parameters
Function Run-MSBuild {
	param(
		[string]$SolutionPath,
		[string]$Name,
		[string]$Configuration,
		[string]$Platform,
		[string]$Target = "Build",
		[string]$Inputs = ""
	)

	# Construct options in a structured manner
	$options = @(
		"/m:4",
		"/p:Configuration=`"$Configuration`"",
		"/p:Platform=`"$Platform`"",
		"/t:`"$Target`""
	)

	if ($Inputs) {
		$options += "/p:Inputs=`"$Inputs`""
	}

	$options += (Join-Path -Path $SolutionPath -ChildPath $Name)

	# Execute MSBuild with the options
	Invoke-Expression -Command ("msbuild.exe " + [string]::Join(" ", $options))

	if ($LASTEXITCODE -ne 0) {
		Write-Host -ForegroundColor Red "ERROR: MSBuild failed, code:" $LASTEXITCODE
		Exit $LASTEXITCODE
	}
}

# Function to run MSBuild for SDV analysis with specific parameters
Function Run-MSBuildSDV {
	param(
		[string]$SolutionPath,
		[string]$Name,
		[string]$Configuration,
		[string]$Platform
	)

	$basepath = Get-Location
	$versionpath = Join-Path -Path $SolutionPath -ChildPath "version"
	$projpath = Join-Path -Path $SolutionPath -ChildPath $Name
	Set-Location $projpath

	$project = [string]::Format("{0}.vcxproj", $Name)
	Run-MSBuild $versionpath "version.vcxproj" $Configuration $Platform "Build"
	Run-MSBuild $projpath $project $Configuration $Platform "Build"
	Run-MSBuild $projpath $project $Configuration $Platform "sdv" "/clean"
	Run-MSBuild $projpath $project $Configuration $Platform "sdv" "/check:default.sdv /debug"
	Run-MSBuild $projpath $project $Configuration $Platform "dvl"

	$refine = Join-Path -Path $projpath -ChildPath "refine.sdv"
	if (Test-Path -Path $refine -PathType Leaf) {
		Run-MSBuild $projpath $project $Configuration $Platform "sdv" "/refine"
	}

	Copy-Item "*DVL*" -Destination $SolutionPath

	Set-Location $basepath
}

# Main script body
$configuration = @{
	"free" = "$ConfigurationBase Release";
	"checked" = "$ConfigurationBase Debug";
	"sdv" = "$ConfigurationBase Release"
}
$platform = @{ "x86" = "Win32"; "x64" = "x64" }
$solutionpath = Resolve-Path $SolutionDir

Set-ExecutionPolicy -Scope CurrentUser -Force Bypass

if ($Type -eq "free" -or $Type -eq "checked") {
	Run-MSBuild $solutionpath "$SolutionName.sln" $configuration[$Type] $platform[$Arch]
}
elseif ($Type -eq "sdv") {
	$archivepath = "xenvbd"

	if (-Not (Test-Path -Path $archivepath)) {
		New-Item -Name $archivepath -ItemType Directory | Out-Null
	}

	Run-MSBuildSDV $solutionpath "xencrsh" $configuration["sdv"] $platform[$Arch]
	Run-MSBuildSDV $solutionpath "xendisk" $configuration["sdv"] $platform[$Arch]
	Run-MSBuildSDV $solutionpath "xenvbd" $configuration["sdv"] $platform[$Arch]

	Copy-Item -Path (Join-Path -Path $SolutionPath -ChildPath "*DVL*") -Destination $archivepath
}
