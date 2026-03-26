Param(
  [Parameter(Mandatory = $true)] [string]$Repo,
  [Parameter(Mandatory = $true)] [string]$NetlifyAuthToken,
  [Parameter(Mandatory = $true)] [string]$NetlifySiteId,
  [Parameter(Mandatory = $true)] [string]$ApiOrigin,
  [Parameter(Mandatory = $true)] [string]$AzureWebAppName,
  [Parameter(Mandatory = $true)] [string]$AzureWebAppPublishProfilePath
)

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "GitHub CLI (gh) is required. Install from https://cli.github.com/"
}

if (-not (Test-Path $AzureWebAppPublishProfilePath)) {
  throw "Publish profile file not found: $AzureWebAppPublishProfilePath"
}

$publishProfile = Get-Content -Raw -Path $AzureWebAppPublishProfilePath

Write-Host "Setting repository secrets for $Repo ..."

$NetlifyAuthToken | gh secret set NETLIFY_AUTH_TOKEN --repo $Repo
$NetlifySiteId | gh secret set NETLIFY_SITE_ID --repo $Repo
$ApiOrigin | gh secret set API_ORIGIN --repo $Repo
$AzureWebAppName | gh secret set AZURE_WEBAPP_NAME --repo $Repo
$publishProfile | gh secret set AZURE_WEBAPP_PUBLISH_PROFILE --repo $Repo

Write-Host "Done. Secrets configured for $Repo"
