<#
.SYNOPSIS
Diagnose Windows Codex -> remote Linux/NUC MCP stdio connectivity over OpenSSH.

.DESCRIPTION
Runs staged read-only checks separating:
1. Codex config.toml validation (missing block vs legacy wsl.exe vs ssh.exe)
2. OpenSSH prerequisite & clean stdout check (detects .bashrc/MOTD noise)
3. Remote `ctf-mcp-admin diagnose-mcp` (tool schema fingerprints, runtime DB, Docker hygiene)
4. Live MCP stdio JSON-RPC handshake (`initialize`, `tools/list`, optional `run.describe`)
5. Optional `vdp.test(operation="check_environment")` (only when -RunCheckEnvironment is passed)

Never prints private keys, tokens, or secret environment values.
#>
[CmdletBinding()]
param(
    [string]$SshTarget = "",
    [string]$IdentityFile = "",
    [string]$RemoteRuntimeDir = "~/ctf-vdp-harness-runtime",
    [string]$RemoteRepoDir = "~/ctf-vdp-harness",
    [string]$RemoteConfig = "",
    [string]$RunId = "",
    [string]$TargetProfile = "",
    [string]$ServerName = "ctf_vdp_harness",
    [string]$CodexConfigPath = "$env:USERPROFILE\.codex\config.toml",
    [switch]$PrintCodexToml,
    [switch]$CheckDocker,
    [switch]$RunCheckEnvironment
)

$ErrorActionPreference = "Stop"
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom

function Write-TomlSnippet {
    param(
        [string]$Target,
        [string]$KeyPath,
        [string]$Launcher,
        [string]$ConfigPath,
        [string]$Name
    )
    $effTarget = if ($Target) { $Target } else { "<NUC_USER>@<NUC_HOST>" }
    $remoteUser = if ($Target -match '^([^@]+)@') { $Matches[1] } else { "<NUC_USER>" }
    $effLauncher = if ($Launcher -match '^~/(.*)$') { "/home/$remoteUser/$($Matches[1])" } else { $Launcher }
    $effCfgRaw = if ($ConfigPath) { $ConfigPath } else { "~/ctf-vdp-harness-runtime/config.vdp-weblate.json" }
    $effCfg = if ($effCfgRaw -match '^~/(.*)$') { "/home/$remoteUser/$($Matches[1])" } else { $effCfgRaw }
    $effKey = if ($KeyPath) { $KeyPath } else { 'C:\Users\<USER>\.ssh\<KEY_FILE>' }
    Write-Output "[mcp_servers.$Name]"
    Write-Output "command = 'C:\WINDOWS\System32\OpenSSH\ssh.exe'"
    Write-Output "args = ["
    Write-Output '  "-T",'
    Write-Output "  `"-i`", '$effKey',"
    Write-Output '  "-o", "BatchMode=yes",'
    Write-Output '  "-o", "StrictHostKeyChecking=yes",'
    Write-Output '  "-o", "IdentitiesOnly=yes",'
    Write-Output '  "-o", "ServerAliveInterval=30",'
    Write-Output '  "-o", "ServerAliveCountMax=3",'
    Write-Output '  "-o", "ConnectTimeout=10",'
    Write-Output "  `"$effTarget`","
    Write-Output "  `"$effLauncher`","
    Write-Output "  `"--config`", `"$effCfg`","
    Write-Output '  "--allow-dynamic",'
    Write-Output "]"
    Write-Output "startup_timeout_sec = 30"
    Write-Output "tool_timeout_sec = 360"
}

$launcherPath = "$RemoteRuntimeDir/launch-mcp-stdio.sh"
if (-not $RemoteConfig) {
    $RemoteConfig = "$RemoteRuntimeDir/config.vdp-weblate.json"
}

if ($PrintCodexToml) {
    Write-TomlSnippet -Target $SshTarget -KeyPath $IdentityFile -Launcher $launcherPath -ConfigPath $RemoteConfig -Name $ServerName
    exit 0
}

$report = [ordered]@{
    schema = "nuc-mcp-diagnostics/1"
    server_name = $ServerName
    codex_config = [ordered]@{ path = $CodexConfigPath; exists = (Test-Path $CodexConfigPath); status = "unknown" }
    ssh_prereq = [ordered]@{ ok = $false }
    ssh_clean_stdout = [ordered]@{ ok = $false }
    remote_diagnose = $null
    mcp_handshake = [ordered]@{ ok = $false; tools = @(); tool_schemas = [ordered]@{} }
    lingering_server_processes = $null
    issues = @()
}

# 1. Inspect Codex config.toml
if (Test-Path $CodexConfigPath) {
    $cfgText = [System.IO.File]::ReadAllText($CodexConfigPath, $utf8NoBom)
    $hdrRegex = "(?ms)^\[mcp_servers\.$([regex]::Escape($ServerName))\](.*?)(?=^\[|\z)"
    $secMatch = [regex]::Match($cfgText, $hdrRegex)
    if ($secMatch.Success) {
        $secBody = $secMatch.Value
        if ($secBody -match "wsl\.exe") {
            $report.codex_config.status = "legacy_wsl_detected"
            $report.issues += "codex_config_legacy_wsl: [mcp_servers.$ServerName] references wsl.exe; update it to ssh.exe."
        } else {
            $report.codex_config.status = "configured"
        }
    } else {
        $report.codex_config.status = "missing_server_block"
        $report.issues += "codex_config_missing: [mcp_servers.$ServerName] is absent from $CodexConfigPath."
    }
} else {
    $report.codex_config.status = "file_missing"
    $report.issues += "codex_config_missing: $CodexConfigPath does not exist."
}

# 2. SSH prerequisite check
$sshExe = (Get-Command ssh.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $sshExe) { $sshExe = "C:\WINDOWS\System32\OpenSSH\ssh.exe" }
if (-not (Test-Path $sshExe)) {
    $report.issues += "ssh_missing: OpenSSH ssh.exe not found."
    $report | ConvertTo-Json -Depth 6
    exit 1
}
if (-not $SshTarget -or -not $IdentityFile) {
    $report.issues += "missing_arguments: pass -SshTarget <user@host> and -IdentityFile <path>."
    $report | ConvertTo-Json -Depth 6
    exit 1
}
if (-not (Test-Path $IdentityFile)) {
    $report.issues += "ssh_key_missing: IdentityFile not found at $IdentityFile."
    $report | ConvertTo-Json -Depth 6
    exit 1
}
$report.ssh_prereq = [ordered]@{ ok = $true; ssh_exe = $sshExe; target = $SshTarget }

$sshBaseArgs = @(
    "-T",
    "-i", $IdentityFile,
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "-o", "ConnectTimeout=10",
    $SshTarget
)

# 3. Clean stdout test
$cleanOut = & $sshExe @sshBaseArgs "printf '__CTF_MCP_SSH_OK__\n'" 2>&1
$cleanExit = $LASTEXITCODE
if ($cleanExit -ne 0) {
    $report.issues += "ssh_auth_or_hostkey_error: ssh exited $cleanExit ($($cleanOut -join ' '))"
    $report | ConvertTo-Json -Depth 6
    exit 1
}
if (($cleanOut | Out-String).Trim() -ne "__CTF_MCP_SSH_OK__") {
    $report.issues += "stdout_pollution: SSH login emitted extra stdout before MCP JSON-RPC; inspect remote ~/.bashrc or /etc/motd."
    $report.ssh_clean_stdout = [ordered]@{ ok = $false; raw = ($cleanOut | Out-String).Trim() }
} else {
    $report.ssh_clean_stdout = [ordered]@{ ok = $true }
}

# 4. Remote ctf-mcp-admin diagnose-mcp
$diagCmd = "set -a && source $RemoteRuntimeDir/.env && set +a && $RemoteRepoDir/.venv/bin/ctf-mcp-admin diagnose-mcp --config $RemoteConfig"
if ($RunId) { $diagCmd += " --active-run $RunId" }
if ($CheckDocker) { $diagCmd += " --check-docker" }
$remoteDiagRaw = & $sshExe @sshBaseArgs $diagCmd 2>&1
$remoteDiagExit = $LASTEXITCODE
try {
    $report.remote_diagnose = ($remoteDiagRaw | Out-String) | ConvertFrom-Json
    if ($remoteDiagExit -ne 0 -or -not $report.remote_diagnose.healthy) {
        $report.issues += "remote_diagnose_unhealthy: inspect remote_diagnose.issues."
    }
} catch {
    $report.remote_diagnose = [ordered]@{ exit_code = $remoteDiagExit; raw = ($remoteDiagRaw | Out-String).Trim() }
    $report.issues += "remote_diagnose_failed: could not parse JSON from diagnose-mcp."
}

# 5. Live MCP stdio handshake via ssh.exe
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $sshExe
$escapedArgs = ($sshBaseArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join " "
$psi.Arguments = "$escapedArgs $launcherPath --config $RemoteConfig --allow-dynamic"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = $utf8NoBom
$psi.StandardErrorEncoding = $utf8NoBom

$proc = [System.Diagnostics.Process]::Start($psi)
try {
    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"nuc-mcp-diag","version":"1.0"}}}')
    $proc.StandardInput.Flush()
    $initLine = $proc.StandardOutput.ReadLine()
    if (-not $initLine) {
        throw "transport_closed_on_initialize"
    }
    $initObj = $initLine | ConvertFrom-Json

    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}')
    $proc.StandardInput.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
    $proc.StandardInput.Flush()
    $toolsLine = $proc.StandardOutput.ReadLine()
    if (-not $toolsLine) {
        throw "transport_closed_on_tools_list"
    }
    $toolsObj = $toolsLine | ConvertFrom-Json
    $toolNames = @($toolsObj.result.tools | ForEach-Object { $_.name } | Sort-Object)
    $liveSchemas = [ordered]@{}
    $schemaDiffs = @()
    foreach ($t in ($toolsObj.result.tools | Sort-Object -Property name)) {
        $props = @()
        if ($null -ne $t.inputSchema.properties) {
            $props = @($t.inputSchema.properties.PSObject.Properties.Name | Sort-Object)
        }
        $req = @()
        if ($null -ne $t.inputSchema.required) {
            $req = @($t.inputSchema.required | ForEach-Object { [string]$_ })
        }
        $addProps = $true
        if ($null -ne $t.inputSchema.additionalProperties) {
            $addProps = [bool]$t.inputSchema.additionalProperties
        }
        $liveSchemas[$t.name] = [ordered]@{
            properties = $props
            required = $req
            additional_properties = $addProps
        }
    }
    $schemaMatch = $null
    if ($null -ne $report.remote_diagnose -and $null -ne $report.remote_diagnose.tool_schemas) {
        $schemaMatch = $true
        $remoteToolNames = @($report.remote_diagnose.tool_schemas.PSObject.Properties.Name | Sort-Object)
        if (($toolNames -join ",") -ne ($remoteToolNames -join ",")) {
            $schemaMatch = $false
            $schemaDiffs += "tool_names_mismatch: live=[$($toolNames -join ',')] remote=[$($remoteToolNames -join ',')]"
        } else {
            foreach ($tname in $toolNames) {
                $lt = $liveSchemas[$tname]
                $rt = $report.remote_diagnose.tool_schemas.$tname
                $rProps = @($rt.properties | ForEach-Object { [string]$_ } | Sort-Object)
                $rReq = @($rt.required | ForEach-Object { [string]$_ })
                $rAdd = [bool]$rt.additional_properties
                if ((($lt.properties -join ",") -ne ($rProps -join ",")) -or (($lt.required -join ",") -ne ($rReq -join ",")) -or ($lt.additional_properties -ne $rAdd)) {
                    $schemaMatch = $false
                    $schemaDiffs += "tool_schema_mismatch:$tname"
                }
            }
        }
        if (-not $schemaMatch) {
            $report.issues += "schema_mismatch_or_extra_forbidden: $($schemaDiffs -join '; ')"
        }
    }
    $report.mcp_handshake = [ordered]@{
        ok = $true
        server_info = $initObj.result.serverInfo
        tools = $toolNames
        tool_schemas = $liveSchemas
        schema_match = $schemaMatch
        schema_diffs = $schemaDiffs
        run_describe = $null
        check_environment = $null
    }

    if ($RunId) {
        $reqDesc = @{
            jsonrpc = "2.0"
            id = 3
            method = "tools/call"
            params = @{ name = "run.describe"; arguments = @{ run_id = $RunId } }
        } | ConvertTo-Json -Depth 6 -Compress
        $proc.StandardInput.WriteLine($reqDesc)
        $proc.StandardInput.Flush()
        $descLine = $proc.StandardOutput.ReadLine()
        if ($descLine) {
            $descResp = $descLine | ConvertFrom-Json
            $sc = $descResp.result.structuredContent
            $report.mcp_handshake.run_describe = [ordered]@{
                run_id = $sc.run_id
                mode = $sc.mode
                revision = $sc.revision
                guest_health = $sc.guest_health
                visible_mcp_tools = $sc.visible_mcp_tools
            }
            if ($RunCheckEnvironment -and $TargetProfile -and $sc.visible_mcp_tools -contains "vdp.test") {
                $reqChk = @{
                    jsonrpc = "2.0"
                    id = 4
                    method = "tools/call"
                    params = @{
                        name = "vdp.test"
                        arguments = @{
                            run_id = $RunId
                            request_id = "diag-check-env-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
                            expected_revision = [int]$sc.revision
                            operation = "check_environment"
                            arguments = @{ target_profile = $TargetProfile }
                        }
                    }
                } | ConvertTo-Json -Depth 8 -Compress
                $proc.StandardInput.WriteLine($reqChk)
                $proc.StandardInput.Flush()
                $chkLine = $proc.StandardOutput.ReadLine()
                if ($chkLine) {
                    $chkResp = $chkLine | ConvertFrom-Json
                    $report.mcp_handshake.check_environment = $chkResp.result.structuredContent.status
                }
            }
        }
    }
    $proc.StandardInput.Close()
    $null = $proc.WaitForExit(10000)
} catch {
    $stderrTail = ""
    try { $stderrTail = $proc.StandardError.ReadToEnd() } catch {}
    $report.mcp_handshake.ok = $false
    $errMsg = $_.Exception.Message
    if ($errMsg -like "transport_closed_on_*") {
        $report.issues += "${errMsg}: stderr=$($stderrTail.Trim())"
    } else {
        $report.issues += "mcp_handshake_failed: $errMsg | stderr=$($stderrTail.Trim())"
    }
} finally {
    if (-not $proc.HasExited) {
        try { $proc.Kill() } catch {}
    }
}

$lingerOut = & $sshExe @sshBaseArgs "pgrep -af '[c]tf-mcp-server' || true" 2>&1
$lingerLines = @($lingerOut | Where-Object { $_ -and $_.ToString().Trim() })
$report.lingering_server_processes = $lingerLines
if ($lingerLines.Count -gt 0) {
    $report.issues += "lingering_mcp_server_processes: $($lingerLines.Count) lingering ctf-mcp-server process(es) found."
}

$report | ConvertTo-Json -Depth 8
if ($report.issues.Count -gt 0) {
    exit 1
}
exit 0
