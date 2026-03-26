Param(
  [Parameter(Mandatory = $true)] [string]$Repo,
  [Parameter(Mandatory = $true)] [string]$VercelToken,
  [Parameter(Mandatory = $true)] [string]$VercelOrgId,
  [Parameter(Mandatory = $true)] [string]$VercelProjectId,
  [Parameter(Mandatory = $true)] [string]$BackendDeployHookUrl,
  [Parameter(Mandatory = $true)] [string]$BackendOrigin
)

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "GitHub CLI (gh) is required. Install from https://cli.github.com/"
}

Write-Host "Setting repository secrets for $Repo ..."

$VercelToken | gh secret set VERCEL_TOKEN --repo $Repo
$VercelOrgId | gh secret set VERCEL_ORG_ID --repo $Repo
$VercelProjectId | gh secret set VERCEL_PROJECT_ID --repo $Repo
$BackendDeployHookUrl | gh secret set BACKEND_DEPLOY_HOOK_URL --repo $Repo
$BackendOrigin | gh secret set BACKEND_ORIGIN --repo $Repo

Write-Host "Done. Vercel + backend deployment secrets configured for $Repo"