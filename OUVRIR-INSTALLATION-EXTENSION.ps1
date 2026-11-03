# Assistant d'installation locale : ouvre uniquement les reglages et le dossier.
# Il ne peut pas activer le mode developpeur ni installer une extension sans action utilisateur.
param([ValidateSet('Edge','Chrome')][string]$Navigateur='Edge')
$racine = Split-Path -Parent $MyInvocation.MyCommand.Path
$dossier = Join-Path $racine 'chrome-extension'
if (-not (Test-Path (Join-Path $dossier 'manifest.json'))) {
    Write-Error 'Dossier chrome-extension introuvable a cote du script.'
    exit 1
}
Start-Process explorer.exe -ArgumentList ('"' + $dossier + '"')
if ($Navigateur -eq 'Edge') {
    Start-Process 'msedge.exe' 'edge://extensions'
} else {
    Start-Process 'chrome.exe' 'chrome://extensions'
}
Write-Host 'Activez manuellement Mode developpeur, puis Charger extension non empaquetee.'
Write-Host ('Selectionnez : ' + $dossier)
