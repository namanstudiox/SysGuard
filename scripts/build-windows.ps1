# Build SysGuard for Windows: NSIS installer (.exe, x64)
# Prereqs: Node.js >= 18 on Windows (or run electron-builder on any OS)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

Write-Host '==> Installing dependencies (production + dev for electron-builder)' -ForegroundColor Cyan
npm install

Write-Host '==> Building NSIS installer (x64)' -ForegroundColor Cyan
npx electron-builder --win nsis --x64

Write-Host ''
Write-Host 'Done. Artifacts are in .\release:'
Get-ChildItem .\release -Filter *.exe | Select-Object -ExpandProperty Name
