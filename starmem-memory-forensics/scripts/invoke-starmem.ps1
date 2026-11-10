[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$Image,
    [Parameter(Mandatory = $true)] [ValidatePattern('^[a-z0-9-]+$')] [string]$Plugin,
    [ValidateSet('Table', 'Json', 'Csv')] [string]$Format = 'Json',
    [string]$ReportPath,
    [ValidateRange(0, 256)] [int]$Threads = 2,
    [string[]]$SymbolPath = @(),
    [string]$CachePath,
    [string[]]$PluginArgs = @(),
    [string]$Binary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-StarMemBinary {
    param([string]$Requested)
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($Requested)) { $candidates.Add($Requested) }
    if (-not [string]::IsNullOrWhiteSpace($env:STARMEM_BIN)) { $candidates.Add($env:STARMEM_BIN) }
    $command = Get-Command starmem -CommandType Application -ErrorAction SilentlyContinue
    if ($command) { $candidates.Add($command.Source) }
    $current = (Get-Location).Path
    $candidates.Add((Join-Path $current 'target\release\starmem.exe'))
    $candidates.Add((Join-Path $current 'target\debug\starmem.exe'))
    $candidates.Add('E:\mem\target\release\starmem.exe')
    $candidates.Add('E:\mem\target\debug\starmem.exe')
    foreach ($candidate in $candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw '找不到 starmem 可执行文件。请使用 -Binary、STARMEM_BIN，或先在 StarMem 源码目录构建 release。'
}

function Ensure-ParentDirectory {
    param([string]$FilePath)
    $parent = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($FilePath))
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
}

$starmem = Resolve-StarMemBinary -Requested $Binary
if (-not (Test-Path -LiteralPath $Image -PathType Leaf)) { throw "内存镜像不存在：$Image" }
$imagePath = (Resolve-Path -LiteralPath $Image).Path
if (($Format -eq 'Csv') -and [string]::IsNullOrWhiteSpace($ReportPath)) {
    throw 'CSV 模式必须指定 -ReportPath。'
}
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) { Ensure-ParentDirectory -FilePath $ReportPath }

$arguments = [System.Collections.Generic.List[string]]::new()
$arguments.Add('--threads')
$arguments.Add($Threads.ToString([System.Globalization.CultureInfo]::InvariantCulture))
if ($Format -eq 'Json') { $arguments.Add('--json') }
if ($Format -eq 'Csv') {
    $arguments.Add('--csv')
    $arguments.Add([System.IO.Path]::GetFullPath($ReportPath))
}
$arguments.Add($Plugin)
$arguments.Add($imagePath)
foreach ($path in $SymbolPath) {
    if ([string]::IsNullOrWhiteSpace($path)) { continue }
    $arguments.Add('--symbol-path')
    $arguments.Add($path)
}
if (-not [string]::IsNullOrWhiteSpace($CachePath)) {
    [System.IO.Directory]::CreateDirectory($CachePath) | Out-Null
    $arguments.Add('--cache')
    $arguments.Add([System.IO.Path]::GetFullPath($CachePath))
}
foreach ($argument in $PluginArgs) { $arguments.Add($argument) }

if (($Format -eq 'Json') -and -not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $stdout = @(& $starmem @arguments 2> $stderrPath)
        $exitCode = $LASTEXITCODE
        $stderr = [System.IO.File]::ReadAllText($stderrPath)
        if ($exitCode -ne 0) { throw "StarMem 失败（退出码 $exitCode）：$stderr" }
        $text = [string]::Join([Environment]::NewLine, $stdout)
        [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($ReportPath), $text, [System.Text.UTF8Encoding]::new($false))
    }
    finally {
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}
else {
    & $starmem @arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "StarMem 失败（退出码 $exitCode）。" }
}

if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    $resolvedReport = [System.IO.Path]::GetFullPath($ReportPath)
    if (-not (Test-Path -LiteralPath $resolvedReport -PathType Leaf)) { throw "StarMem 未生成预期报告：$resolvedReport" }
    $report = Get-Item -LiteralPath $resolvedReport
    if ($report.Length -eq 0) { throw "StarMem 生成了空报告：$resolvedReport" }
    $hash = Get-FileHash -LiteralPath $resolvedReport -Algorithm SHA256
    [pscustomobject]@{
        Plugin = $Plugin
        Image = $imagePath
        Report = $resolvedReport
        Bytes = $report.Length
        Sha256 = $hash.Hash
        Threads = $Threads
    }
}
