#Requires -Version 5.1
<#
.SYNOPSIS
    Intune Firewall Policy Exporter
    Esporta le policy Firewall da Intune via Graph e genera i report con Python.

.PARAMETER OutputFolder
    Cartella di destinazione. Default: .\IntuneFirewallExport_<timestamp>

.PARAMETER TenantId
    Opzionale: forza tenant specifico (utile con PIM).

.PARAMETER SkipModuleInstall
    Non installare moduli PS mancanti.

.PARAMETER FromJson
    Salta Graph e genera solo i report da un JSON esistente.

.EXAMPLE
    .\Export-IntuneFirewall-Complete.ps1
    .\Export-IntuneFirewall-Complete.ps1 -TenantId "contoso.onmicrosoft.com"
    .\Export-IntuneFirewall-Complete.ps1 -FromJson ".\export\FirewallPolicies_Full.json"
#>

[CmdletBinding()]
param(
    [string]$OutputFolder    = "",
    [string]$TenantId        = "",
    [switch]$SkipModuleInstall,
    [string]$FromJson        = ""
)

if ($OutputFolder -eq "") {
    $OutputFolder = ".\IntuneFirewallExport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}

# ============================================================================
#  HELPERS
# ============================================================================
function Write-Step {
    param([int]$n, [string]$msg)
    Write-Host ""
    Write-Host "[$n] $msg" -ForegroundColor Cyan
}
function Write-OK   { param([string]$msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    [!!] $msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$msg) Write-Host "    [XX] $msg" -ForegroundColor Red }
function Write-Info { param([string]$msg) Write-Host "    [ ] $msg" -ForegroundColor Gray }

function Write-Banner {
    param([string]$title, [string]$color)
    if ($color -eq "") { $color = "Cyan" }
    $line = "=" * 66
    Write-Host ""
    Write-Host $line -ForegroundColor $color
    Write-Host "  $title" -ForegroundColor $color
    Write-Host $line -ForegroundColor $color
}

function Abort {
    param([string]$reason)
    Write-Fail $reason
    Write-Host "[ABORT] Correggi il problema e riprova." -ForegroundColor Red
    exit 1
}

function Invoke-GraphGetAllPages {
    param([string]$Uri)
    $results = @()
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
        if ($resp.value) { $results += $resp.value }
        $nextLink = $resp.'@odata.nextLink'
        while ($nextLink) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
            if ($resp.value) { $results += $resp.value }
            $nextLink = $resp.'@odata.nextLink'
        }
    }
    catch { Write-Warn "Errore $Uri : $($_.Exception.Message)" }
    return $results
}

# ============================================================================
Write-Banner "Intune Firewall Policy Exporter" "Cyan"
Write-Info "Avvio: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Info "Report generati da Python (parser affidabile)"

# ============================================================================
#  MODALITA -FromJson: salta tutto Graph, vai dritto ai report
# ============================================================================
if ($FromJson -ne "") {
    Write-Info "Modalita -FromJson attiva"
    if (-not (Test-Path $FromJson)) { Abort "File non trovato: $FromJson" }
    $jsonPath = (Resolve-Path $FromJson).Path
    Write-OK "JSON: $jsonPath"

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }
    $resolvedFolder = (Resolve-Path $OutputFolder).Path
}
else {
    # ============================================================================
    #  FASE 1 - AMBIENTE
    # ============================================================================
    Write-Step 1 "Controllo ambiente"
    if ([System.Environment]::OSVersion.Platform.ToString() -ne "Win32NT") { Abort "Richiede Windows." }
    Write-OK "Windows OK"
    if ($PSVersionTable.PSVersion.Major -lt 5) { Abort "Richiede PowerShell 5.1+" }
    Write-OK "PowerShell $($PSVersionTable.PSVersion) OK"
    if ([System.IntPtr]::Size -ne 8) { Abort "Richiede PowerShell 64-bit." }
    Write-OK "64-bit OK"
    try { $null = [System.Net.Dns]::GetHostAddresses("graph.microsoft.com"); Write-OK "Connettivita Graph OK" }
    catch { Abort "Impossibile raggiungere graph.microsoft.com" }

    # ============================================================================
    #  FASE 2 - EXECUTION POLICY
    # ============================================================================
    Write-Step 2 "Execution Policy"
    $blockingPolicies = @("Restricted", "AllSigned")
    $ep = (Get-ExecutionPolicy).ToString()
    Write-Info "Policy effettiva: $ep"
    if ($blockingPolicies -contains $ep) {
        $gpBlock = $false
        foreach ($s in @("MachinePolicy", "UserPolicy")) {
            $p = (Get-ExecutionPolicy -Scope $s -ErrorAction SilentlyContinue).ToString()
            if ($blockingPolicies -contains $p) { Write-Warn "GPO scope $s = $p"; $gpBlock = $true }
        }
        if ($gpBlock) {
            Write-Warn "Usa: powershell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
            Abort "Execution Policy imposta da GPO."
        }
        try { Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop; Write-OK "RemoteSigned impostato" }
        catch { Set-ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue; Write-OK "Bypass per questa sessione" }
    }
    else { Write-OK "Execution Policy '$ep' - OK" }

    # ============================================================================
    #  FASE 3 - MODULI MICROSOFT GRAPH
    # ============================================================================
    Write-Step 3 "Moduli Microsoft Graph"
    $requiredMods = @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement")
    try {
        $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
        if (-not $nuget -or ([Version]$nuget.Version -lt [Version]"2.8.5.201")) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
            Write-OK "NuGet installato"
        }
        $gal = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($gal -and $gal.InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    }
    catch {}
    foreach ($m in $requiredMods) {
        $inst = Get-Module -ListAvailable -Name $m | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $inst -or $inst.Version -lt [Version]"2.0.0") {
            if ($SkipModuleInstall) { Abort "Modulo $m mancante." }
            Write-Info "Installazione $m..."
            try {
                Install-Module -Name $m -MinimumVersion "2.0.0" -Scope CurrentUser `
                               -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
                Write-OK "$m installato"
            }
            catch { Abort "Impossibile installare $m : $($_.Exception.Message)" }
        }
        else { Write-OK "$m v$($inst.Version) OK" }
        try { Import-Module $m -ErrorAction Stop }
        catch { Abort "Import $m fallito: $($_.Exception.Message)" }
    }
    foreach ($lm in @("AzureAD", "AzureADPreview", "MSOnline")) {
        if (Get-Module -Name $lm -ErrorAction SilentlyContinue) {
            Remove-Module -Name $lm -Force -ErrorAction SilentlyContinue
            Write-OK "Rimosso ADAL legacy: $lm"
        }
    }

    # ============================================================================
    #  FASE 4 - AUTENTICAZIONE
    # ============================================================================
    Write-Step 4 "Autenticazione Microsoft Graph"
    Write-Warn "Ricordati di attivare il ruolo PIM prima di continuare!"
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        if ($TenantId -ne "") {
            Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" `
                            -TenantId $TenantId -ErrorAction Stop
        }
        else {
            Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -ErrorAction Stop
        }
        $ctx = Get-MgContext
        if (-not $ctx) { throw "Context null." }
        Write-OK "Account : $($ctx.Account)"
        Write-OK "Tenant  : $($ctx.TenantId)"
    }
    catch { Abort "Autenticazione fallita: $($_.Exception.Message)" }

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }
    $resolvedFolder = (Resolve-Path $OutputFolder).Path

    # ============================================================================
    #  FASE 5 - RECUPERO POLICY
    # ============================================================================
    Write-Step 5 "Recupero policy da Intune"
    $AllPolicies = New-Object System.Collections.Generic.List[PSObject]

    Write-Info "[5a] Intent-based policies..."
    $intents = Invoke-GraphGetAllPages "https://graph.microsoft.com/beta/deviceManagement/intents"
    Write-Info "     $($intents.Count) trovate"
    foreach ($i in $intents) {
        $AllPolicies.Add((New-Object PSObject -Property @{
            Source="Intent"; Id=$i.id; DisplayName=$i.displayName; Description=$i.description
            TemplateId=$i.templateId; LastModified=$i.lastModifiedDateTime
            CreatedDateTime=$i.createdDateTime; RoleScopeTagIds=($i.roleScopeTagIds -join ", ")
            AssignedGroups=@(); Settings=$null
        }))
    }

    Write-Info "[5b] Settings Catalog policies..."
    $scPolicies = Invoke-GraphGetAllPages "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
    Write-Info "     $($scPolicies.Count) trovate"
    foreach ($scp in $scPolicies) {
        $tId = $null
        if ($null -ne $scp.templateReference) { $tId = $scp.templateReference.templateId }
        $AllPolicies.Add((New-Object PSObject -Property @{
            Source="SettingsCatalog"; Id=$scp.id; DisplayName=$scp.name; Description=$scp.description
            TemplateId=$tId; LastModified=$scp.lastModifiedDateTime
            CreatedDateTime=$scp.createdDateTime; RoleScopeTagIds=($scp.roleScopeTagIds -join ", ")
            AssignedGroups=@(); Settings=$null
        }))
    }
    Write-OK "Totale policy: $($AllPolicies.Count)"

    # ============================================================================
    #  FASE 6 - FILTRO E ARRICCHIMENTO
    # ============================================================================
    Write-Step 6 "Filtro policy Firewall e recupero dettagli"
    $fwKeywords = @("Firewall", "firewall", "Windows Defender Firewall")
    $FwPolicies = $AllPolicies | Where-Object {
        $dn = $_.DisplayName; $m = $false
        foreach ($kw in $fwKeywords) { if ($dn -match $kw) { $m = $true; break } }
        $m
    }
    if ($FwPolicies.Count -eq 0) {
        Write-Warn "Nessuna policy Firewall trovata - esporto tutto"
        $FwPolicies = $AllPolicies
    }
    else {
        Write-OK "$($FwPolicies.Count) policy Firewall trovate"
        foreach ($fp in $FwPolicies) { Write-Info "  [$($fp.Source.PadRight(14))] $($fp.DisplayName)" }
    }

    Write-Info "Recupero settings e gruppi..."
    foreach ($fp in $FwPolicies) {
        try {
            $uri = if ($fp.Source -eq "SettingsCatalog") {
                "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($fp.Id)/settings"
            } else {
                "https://graph.microsoft.com/beta/deviceManagement/intents/$($fp.Id)/settings"
            }
            $fp.Settings = Invoke-GraphGetAllPages $uri
        }
        catch { Write-Warn "Settings non recuperabili per '$($fp.DisplayName)'" }

        try {
            $uri = if ($fp.Source -eq "SettingsCatalog") {
                "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($fp.Id)/assignments"
            } else {
                "https://graph.microsoft.com/beta/deviceManagement/intents/$($fp.Id)/assignments"
            }
            $assignments = Invoke-GraphGetAllPages $uri
            $groupNames  = @()
            foreach ($a in $assignments) {
                $target = $a.target
                if ($null -eq $target) { continue }
                $dtype = $target.'@odata.type'
                if ($dtype -match "allDevices")      { $groupNames += "Tutti i dispositivi (All Devices)" }
                elseif ($dtype -match "allLicensed") { $groupNames += "Tutti gli utenti (All Licensed Users)" }
                elseif ($target.groupId) {
                    try {
                        $grp = Invoke-MgGraphRequest -Method GET `
                               -Uri "https://graph.microsoft.com/v1.0/groups/$($target.groupId)" `
                               -ErrorAction SilentlyContinue
                        $groupNames += if ($grp -and $grp.displayName) { $grp.displayName } else { $target.groupId }
                    }
                    catch { $groupNames += $target.groupId }
                }
            }
            $fp.AssignedGroups = $groupNames
            Write-Info "  '$($fp.DisplayName)' -> $($groupNames.Count) gruppi"
        }
        catch { Write-Warn "Gruppi non recuperabili per '$($fp.DisplayName)'" }
    }

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null; Write-Info "Sessione Graph chiusa." } catch {}

    # ============================================================================
    #  FASE 7 - EXPORT JSON
    # ============================================================================
    Write-Step 7 "Export JSON"
    $jsonPath = Join-Path $resolvedFolder "FirewallPolicies_Full.json"
    $FwPolicies | ConvertTo-Json -Depth 25 | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
    Write-OK "JSON -> $jsonPath"
}

# ============================================================================
#  FASE 8 - GENERAZIONE REPORT CON PYTHON
# ============================================================================
Write-Step 8 "Generazione report con Python"

# Trova Python
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") { $pythonCmd = $cmd; break }
    }
    catch {}
}

if (-not $pythonCmd) {
    Write-Warn "Python 3 non trovato. Installa da https://python.org"
    Write-Warn "Poi esegui manualmente:"
    Write-Warn "  python generate_reports.py `"$jsonPath`" `"$resolvedFolder`""
    Write-Warn "Il JSON e comunque disponibile in: $resolvedFolder"
}
else {
    Write-OK "Python: $pythonCmd"

    # Verifica openpyxl
    try {
        $chk = & $pythonCmd -c "import openpyxl; print(openpyxl.__version__)" 2>&1
        Write-OK "openpyxl $chk"
    }
    catch {
        Write-Info "Installazione openpyxl..."
        & $pythonCmd -m pip install openpyxl --quiet 2>&1 | Out-Null
        Write-OK "openpyxl installato"
    }

    # Cerca generate_reports.py nella stessa cartella dello script PS
    $pyScriptSrc = Join-Path $PSScriptRoot "generate_reports.py"
    $pyScriptDst = Join-Path $resolvedFolder "generate_reports.py"

    if (Test-Path $pyScriptSrc) {
        Copy-Item $pyScriptSrc $pyScriptDst -Force
        Write-OK "generate_reports.py copiato nella cartella output"
    }
    elseif (-not (Test-Path $pyScriptDst)) {
        Write-Warn "generate_reports.py non trovato in $PSScriptRoot"
        Write-Warn "Assicurati che generate_reports.py sia nella stessa cartella di questo script PS."
        Abort "generate_reports.py mancante."
    }

    Write-Info "Esecuzione generate_reports.py..."
    try {
        & $pythonCmd $pyScriptDst $jsonPath $resolvedFolder 2>&1 |
            ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        Write-OK "Report generati"
    }
    catch {
        Write-Warn "Errore: $($_.Exception.Message)"
        Write-Warn "Riesegui: $pythonCmd `"$pyScriptDst`" `"$jsonPath`" `"$resolvedFolder`""
    }
}

# ============================================================================
#  RIEPILOGO
# ============================================================================
Write-Banner "Completato" "Green"
Write-Host "  Cartella output: $resolvedFolder" -ForegroundColor Green
Write-Host ""
Write-Host "  File generati:" -ForegroundColor Green
if ($FromJson -eq "") {
    Write-Host "    FirewallPolicies_Full.json      - dati raw Graph" -ForegroundColor Gray
}
Write-Host "    FirewallPolicies_Report.html    - Dashboard interattiva (apri nel browser)" -ForegroundColor Gray
Write-Host "    FirewallPolicies_Rules.csv      - CSV per Power BI / Excel" -ForegroundColor Gray
Write-Host "    FirewallPolicies_Report.xlsx    - Excel multi-foglio" -ForegroundColor Gray
Write-Host ""
Write-Info "Per rigenerare i report senza ri-autenticarsi:"
Write-Info "  .\Export-IntuneFirewall-Complete.ps1 -FromJson `"$jsonPath`""
Write-Host ""
