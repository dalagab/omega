param(
  [int]$MaxScans = 5,
  [int]$MaxBatchSeconds = 900,
  [string]$WorkDir = "C:\osl",
  [switch]$Push,
  [switch]$SkipSourceFollowupReconcile,
  [int]$MaxNewFollowups = 0,
  [int]$MaxCloseFollowups = 100,
  [switch]$NoReset,
  [string]$Repository = "dalagab/omega"
)

$ErrorActionPreference = "Stop"
$started = Get-Date
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..\..")
$worker = Join-Path $repoRoot "tools\security\sigmascope_local_queue_worker.py"

$argsList = @(
  $worker,
  "--work-dir", $WorkDir,
  "--max-scans", [string]$MaxScans,
  "--max-batch-seconds", [string]$MaxBatchSeconds,
  "--repository", $Repository
)
if (-not $NoReset) { $argsList += "--reset-work-dir" }
if ($Push) {
  $argsList += "--push"
  if (-not $SkipSourceFollowupReconcile) {
    $argsList += @(
      "--reconcile-source-followups",
      "--max-new-followups", [string]$MaxNewFollowups,
      "--max-close-followups", [string]$MaxCloseFollowups
    )
  }
}

Write-Host "==> SigmaScope local batch"
Write-Host "+ python $($argsList -join ' ')"
& python @argsList
$exitCode = $LASTEXITCODE
$ended = Get-Date
$elapsed = $ended - $started

$summary = [ordered]@{
  exitCode = $exitCode
  elapsed = $elapsed.ToString()
  workDir = $WorkDir
  maxScans = $MaxScans
  pushed = $false
  previousHead = ""
  newHead = ""
  files = 0
  bytes = 0
  checkedVariants = 0
  auditFail = $null
  auditWarn = $null
  selected = 0
  completed = 0
  failed = 0
  plugins = @()
}

$reportPath = Join-Path $WorkDir "local-sigmascope-queue-worker-report.json"
if (Test-Path $reportPath) {
  $report = Get-Content $reportPath -Raw | ConvertFrom-Json
  if ($report.publication) {
    $summary.pushed = [bool]$report.publication.pushed
    $summary.previousHead = [string]$report.publication.previousHead
    $summary.newHead = [string]$report.publication.newHead
    $summary.files = [int]$report.publication.files
    $summary.bytes = [int64]$report.publication.bytes
    $summary.checkedVariants = [int]$report.publication.validation.checkedVariants
    $summary.auditFail = [int]$report.publication.audit.fail
    $summary.auditWarn = [int]$report.publication.audit.warn
  }
}

$workReports = Join-Path $WorkDir "catalog\security-v2-work\sigmascope-report-*.json"
$pluginRows = @()
Get-ChildItem $workReports -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object {
  $batch = Get-Content $_.FullName -Raw | ConvertFrom-Json
  $summary.selected += [int]$batch.selected
  $summary.completed += [int]$batch.completed
  $summary.failed += [int]$batch.failed
  foreach ($plugin in @($batch.plugins)) {
    $pluginRows += [pscustomobject]@{
      variantId = $plugin.variantId
      name = $plugin.internalName
      source = $plugin.sourceName
      status = $plugin.status
      severity = $plugin.highestSeverity
      seconds = $plugin.elapsedSeconds
      error = $plugin.error
    }
  }
}
$summary.plugins = @($pluginRows | Select-Object -First 20)

Write-Host ""
Write-Host "==> Batch summary"
[pscustomobject]$summary | ConvertTo-Json -Depth 6

if ($exitCode -ne 0) { exit $exitCode }
