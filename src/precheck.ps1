param([switch]$Library)
# Embedded collector: only queries. No files are written on the destination.
$worker = {
    param($r)
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $checks = New-Object 'System.Collections.Generic.List[object]'
    function Add-Check($phase, $name, $state, $detail) {
        $checks.Add([pscustomobject]@{phase=[string]$phase; name=[string]$name; state=[string]$state; detail=[string]$detail})
    }
    function Read-Version([string]$text) {
        if ($text -notmatch '^v?(\d+\.\d+\.\d+(?:\.\d+)?)$') { return $null }
        $parts = @($matches[1].Split('.')); while ($parts.Count -lt 4) { $parts += '0' }
        try { return [version]($parts -join '.') } catch { return $null }
    }
    function Is-CD([string]$name) { return $name -match '(?i)Connect\s*:?\s*Direct' }
    function Test-Free($name, $path, [double]$minimum, $lowState = 'FAIL') {
        try {
            $root = [IO.Path]::GetPathRoot($path)
            if ($root -notmatch '^[A-Za-z]:\\$') { throw "No es un volumen local: $path" }
            $disk = New-Object IO.DriveInfo($root)
            if (!$disk.IsReady) { throw "Volumen inaccesible o no disponible: $root" }
            $free = $disk.AvailableFreeSpace / 1GB
            $state = if ($free -ge $minimum) {'OK'} else {$lowState}
            Add-Check 'Disco' $name $state ('{0:N2} GB libres; minimo {1:N2} GB; {2}' -f $free,$minimum,$root)
        } catch { Add-Check 'Disco' $name 'ERROR' $_.Exception.Message }
    }
    function Test-Acl($name, $path) {
        try {
            $acl = Get-Acl -LiteralPath $path
            $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
            $entries = @($rules | ForEach-Object {
                '{0}: {1} {2}; herencia={3}' -f $_.IdentityReference.Value,$_.AccessControlType,$_.FileSystemRights,$_.IsInherited
            })
            $writeMask = [Security.AccessControl.FileSystemRights]::Write
            $writable = @($rules | Where-Object { $_.IdentityReference.Value -in @('S-1-5-32-544','S-1-5-18') -and $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $writeMask) -eq $writeMask -and !($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) })
            $denied = @($rules | Where-Object { $_.AccessControlType -eq 'Deny' -and ($_.FileSystemRights -band $writeMask) -ne 0 })
            Add-Check 'Permisos' $name $(if ($writable.Count -gt 0 -and !$denied.Count) {'OK'} else {'WARN'}) ("$path; propietario SID: $owner. ACL: " + ($entries -join ' | ') + '. Criterio del precheck: escritura declarada para Administradores/SYSTEM. No prueba acceso efectivo de AP3W.')
        } catch { Add-Check 'Permisos' $name 'ERROR' $_.Exception.Message }
    }
    function Get-TreeBytes([string]$path) {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Enlace/junction omitido: $path. Estimar backup manualmente." }
        [long]$size = 0
        $pending = New-Object 'System.Collections.Generic.Stack[string]'
        $pending.Push($path)
        while ($pending.Count -gt 0) {
            foreach ($entry in (Get-ChildItem -LiteralPath $pending.Pop() -Force)) {
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Enlace/junction omitido: $($entry.FullName). Estimacion incompleta." }
                if ($entry.PSIsContainer) { $pending.Push($entry.FullName) } else { $size += $entry.Length }
            }
        }
        return $size
    }
    function Find-Fixes($roots, [int]$maxDepth = 3) {
        $found = New-Object 'System.Collections.Generic.List[object]'
        $seen = @{}; $visited = 0
        $pending = New-Object 'System.Collections.Generic.Queue[object]'
        foreach ($root in @($roots | Sort-Object -Unique)) {
            if ($root) { $pending.Enqueue([pscustomobject]@{path=[string]$root;depth=0}) }
        }
        while ($pending.Count) {
            $dir = $pending.Dequeue()
            if ($seen.ContainsKey($dir.path)) { continue }
            $seen[$dir.path] = $true
            try {
                if (!(Test-Path -LiteralPath $dir.path -PathType Container)) { continue }
                $item = Get-Item -LiteralPath $dir.path -Force
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                # ponytail: bounded staging discovery; report its scope instead of scanning whole server disks.
                $visited++
                if ($visited -gt 400) { Add-Check 'Instalador' 'Limite de busqueda' 'WARN' 'Busqueda limitada a 400 carpetas; puede haber otros paquetes'; break }
                foreach ($entry in Get-ChildItem -LiteralPath $dir.path -Force) {
                    if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                    if ($entry.PSIsContainer) {
                        if ($dir.depth -lt $maxDepth -and $entry.Name -notin @('Windows','node_modules','target','.git','Reportes')) {
                            $pending.Enqueue([pscustomobject]@{path=$entry.FullName;depth=($dir.depth + 1)})
                        }
                    } elseif ($entry.Extension -eq '.exe' -and $entry.Name -match '(?i)connect.?direct|(?:fp|if)\d') {
                        $meta = $entry.VersionInfo
                        $v = Read-Version $meta.ProductVersion
                        $source = 'Metadatos'
                        if (!$v -and $entry.Name -match '(\d+\.\d+\.\d+\.\d+)') { $v = Read-Version $matches[1]; $source = 'Nombre de archivo' }
                        $found.Add([pscustomobject]@{path=$entry.FullName;version=$v;source=$source;identity=(Is-CD ($meta.ProductName + ' ' + $meta.FileDescription))})
                    }
                }
            } catch { Add-Check 'Instalador' 'Carpeta no consultable' 'WARN' ("$($dir.path): " + $_.Exception.Message) }
        }
        return $found.ToArray()
    }
    function Test-FixCandidates($candidates, $installation) {
        $current = Read-Version $installation.version
        $sameBranch = @($candidates | Where-Object { $_.version -and $current -and $_.version.Major -eq $current.Major -and $_.version.Minor -eq $current.Minor -and $_.version.Build -eq $current.Build } | Sort-Object @{Expression='version';Descending=$true},path)
        $chosen = $sameBranch | Select-Object -First 1
        if (!$chosen) {
            Add-Check 'Instalador' 'Fix disponible' $(if ($current) {'FAIL'} else {'WARN'}) ("$($installation.path): no se encontro un candidato con version de la rama instalada en las carpetas consultadas")
            return
        }
        Add-Check 'Instalador' 'Fix detectado automaticamente' 'INFO' ("$($installation.path) -> $($chosen.path); version $($chosen.version); origen: $($chosen.source)")
        Add-Check 'Instalador' 'Version fix > instalada' $(if ($chosen.version -gt $current) {'OK'} else {'FAIL'}) ("$($installation.path): instalada $current; fix $($chosen.version)")
        if (!$chosen.identity -or $chosen.source -ne 'Metadatos') { Add-Check 'Instalador' 'Identidad/version por confirmar' 'WARN' "$($chosen.path): candidato por nombre; contrastar identidad y version con el paquete IBM aprobado" }
        Add-Check 'Instalador' 'Compatibilidad IBM' 'INFO' 'Comparacion numerica; verificar aplicabilidad y requisitos del fix segun su documentacion'
    }
    # Tests load these exact helpers without querying a computer.
    if ($r.helpers_only) { return }
    $started = (Get-Date).ToString('o')
    $account = switch ($r.environment) { DESA {'AP3WDES'} CERT {'AP3WCER'} PROD {'AP3WPRO'} default {throw 'Ambiente invalido'} }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Add-Check 'Entorno' 'Sesion elevada' $(if ($admin) {'OK'} else {'FAIL'}) $identity.Name
    Add-Check 'Entorno' 'PowerShell' $(if ($PSVersionTable.PSVersion -ge [version]'5.1') {'OK'} else {'FAIL'}) ([string]$PSVersionTable.PSVersion + '; minimo de esta herramienta: 5.1')
    try {
        $ep = Get-ExecutionPolicy
        Add-Check 'Entorno' 'ExecutionPolicy' $(if ($ep -in @('Restricted','AllSigned')) {'WARN'} else {'OK'}) "$ep; no se modifica la politica"
    } catch { Add-Check 'Entorno' 'ExecutionPolicy' 'ERROR' $_.Exception.Message }
    try {
        $strong = @()
        foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
            if (Test-Path -LiteralPath $key) { $strong += $key }
        }
        $sm = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $active = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName').ComputerName
        $configured = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName').ComputerName
        $weak = @()
        if ($sm.PendingFileRenameOperations) { $weak += 'PendingFileRenameOperations' }
        if ($active -ne $configured) { $weak += 'Cambio de nombre pendiente' }
        if ($strong.Count -gt 0) { Add-Check 'Entorno' 'Reinicio pendiente' 'WARN' ($strong -join '; ') }
        elseif ($weak.Count -gt 0) { Add-Check 'Entorno' 'Reinicio pendiente' 'INFO' (($weak -join '; ') + '; senales debiles segun precheck original') }
        else { Add-Check 'Entorno' 'Reinicio pendiente' 'OK' 'Sin indicadores en las claves consultadas' }
    } catch { Add-Check 'Entorno' 'Reinicio pendiente' 'ERROR' $_.Exception.Message }
    $apps = @()
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        try {
            if (Test-Path -LiteralPath $base) {
                foreach ($key in Get-ChildItem -LiteralPath $base) {
                    try { $apps += Get-ItemProperty -LiteralPath $key.PSPath }
                    catch { Add-Check 'Instalacion' 'Lectura registro' 'ERROR' ("$($key.PSChildName): " + $_.Exception.Message) }
                }
            }
        } catch { Add-Check 'Instalacion' 'Lectura registro' 'ERROR' $_.Exception.Message }
    }
    $vc = @($apps | Where-Object { $_.DisplayName -match 'Visual C\+\+.*Redistributable' })
    Add-Check 'Entorno' 'VC++ Redistributable' 'INFO' ((@($vc | ForEach-Object {$_.DisplayName}) -join '; ') + '; comprobar requisitos especificos del fix IBM')
    $cdApps = @($apps | Where-Object { (Is-CD $_.DisplayName) -and $_.DisplayName -notmatch 'File Agent|Web Service|PostgreSQL' })
    $installs = @{}
    $services = @()
    try {
        $services = @(Get-CimInstance Win32_Service)
        foreach ($svc in $services) {
            if (!(Is-CD $svc.DisplayName) -or $svc.DisplayName -match 'File Agent|Web Service|PostgreSQL') { continue }
            if ($svc.PathName -notmatch '^\s*"?(?<exe>[A-Za-z]:\\.*?\\Server\\[^"\r\n]*?\.exe)(?:"|\s|$)') { continue }
            $exe = $matches.exe
            if ($exe -notmatch '^(?<root>.+?)\\Server\\') { continue }
            $root = $matches.root
            if (!$installs.ContainsKey($root)) { $installs[$root] = [pscustomobject]@{path=$root; version=''; source='Servicio motor'; engine=$svc.Name} }
        }
    } catch { Add-Check 'Instalacion' 'Consulta servicios' 'ERROR' $_.Exception.Message }
    foreach ($app in $cdApps) {
        $root = ([string]$app.InstallLocation).TrimEnd('\')
        if ($root -match '^[A-Za-z]:\\') {
            if (!$installs.ContainsKey($root)) { $installs[$root] = [pscustomobject]@{path=$root; version=[string]$app.DisplayVersion; source='Registro'; engine=''} }
            elseif (!$installs[$root].version) { $installs[$root].version = [string]$app.DisplayVersion }
        } else { Add-Check 'Instalacion' 'Registro sin ruta' 'WARN' ("$($app.DisplayName) $($app.DisplayVersion): InstallLocation no disponible; contrastar con el servicio motor") }
    }
    foreach ($inst in $installs.Values) {
        if (!$inst.version -and $inst.engine) {
            try {
                $svc = $services | Where-Object { $_.Name -eq $inst.engine } | Select-Object -First 1
                if ($svc.PathName -match '^\s*"?(?<exe>[A-Za-z]:\\.*?\.exe)(?:"|\s|$)') { $inst.version = [Diagnostics.FileVersionInfo]::GetVersionInfo($matches.exe).ProductVersion }
            } catch { Add-Check 'Instalacion' 'Lectura version' 'ERROR' $_.Exception.Message }
        }
        Add-Check 'Instalacion' 'Instalacion detectada' 'INFO' ("$($inst.path); version=$($inst.version); origen=$($inst.source)")
    }
    if ($installs.Count -eq 0) { Add-Check 'Instalacion' 'Discovery' 'FAIL' 'No se detecto Connect:Direct por servicio motor o registro con ruta' }
    else { Add-Check 'Instalacion' 'Discovery' 'OK' "$($installs.Count) instalacion(es)" }
    $inC = @($installs.Values | Where-Object { $_.path -match '^C:\\' } | ForEach-Object {$_.path})
    try {
        foreach ($base in @('C:\Program Files\IBM','C:\Program Files (x86)\IBM')) {
            if (Test-Path -LiteralPath $base) {
                $inC += @(Get-ChildItem -LiteralPath $base -Directory -Force | Where-Object { Is-CD $_.Name } | ForEach-Object {$_.FullName})
            }
        }
        Add-Check 'Instalacion' 'Politica BCP: fuera de C:' $(if ($inC.Count) {'FAIL'} else {'OK'}) $(if ($inC.Count) {$inC -join '; '} else {'Sin instalaciones o carpetas detectadas en C:'})
    } catch { Add-Check 'Instalacion' 'Politica BCP: fuera de C:' 'ERROR' $_.Exception.Message }
    foreach ($selected in @($installs.Values | Sort-Object path)) {
        Add-Check 'Instalacion' 'Version instalada' $(if (Read-Version $selected.version) {'OK'} else {'WARN'}) ("$($selected.path); $($selected.version)")
        $related = @($services | Where-Object { $_.PathName -match ('^\s*"?' + [regex]::Escape($selected.path.TrimEnd('\') + '\')) })
        if (!$related.Count) { Add-Check 'Instalacion' 'Servicios C:D' 'FAIL' 'No hay servicios asociados a la ruta objetivo' }
        else {
            $running = @($related | Where-Object {$_.State -eq 'Running'}).Count
            Add-Check 'Instalacion' 'Servicios C:D' $(if ($running -eq $related.Count -and $related.Count -ge 5) {'OK'} else {'WARN'}) ("$running/$($related.Count) Running; referencia del script: 5 servicios. " + (($related | ForEach-Object {"$($_.Name)=$($_.State); cuenta=$($_.StartName)"}) -join ' | '))
            $different = @($related | Where-Object {$_.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM')})
            Add-Check 'Instalacion' 'Cuenta de servicios' $(if ($different.Count) {'WARN'} else {'OK'}) $(if ($different.Count) {($different | ForEach-Object {"$($_.Name): $($_.StartName)"}) -join '; '} else {'LocalSystem'})
        }
        $engine = $services | Where-Object {$_.Name -eq $selected.engine} | Select-Object -First 1
        if ($engine -and $engine.State -eq 'Running') {
            try {
                $listeners = @(Get-NetTCPConnection -State Listen)
                foreach ($port in $r.ports) {
                    $found = @($listeners | Where-Object {$_.LocalPort -eq $port})
                    $owned = @($found | Where-Object {$_.OwningProcess -eq $engine.ProcessId})
                    Add-Check 'Instalacion' "Puerto $port" $(if ($owned.Count) {'OK'} else {'WARN'}) $(if ($owned.Count) {"LISTEN; PID motor $($engine.ProcessId)"} elseif ($found.Count) {'En escucha por otro proceso; revisar'} else {'Sin escucha TCP; revisar netmap. No demuestra apertura del firewall'})
                }
            } catch { Add-Check 'Instalacion' 'Puertos TCP' 'ERROR' $_.Exception.Message }
        } else { Add-Check 'Instalacion' 'Puertos TCP' 'WARN' 'No evaluables: motor detenido o no identificado' }
    }
    $resolved = $null
    try {
        $name = $account
        $resolved = (New-Object Security.Principal.NTAccount($name)).Translate([Security.Principal.SecurityIdentifier])
        $full = $resolved.Translate([Security.Principal.NTAccount]).Value
        Add-Check 'Cuenta' 'Cuenta de parchado' 'OK' "$full; $($resolved.Value)"
        $memberships = @()
        foreach ($sid in @('S-1-5-32-547','S-1-5-32-544')) {
            try {
                $group = Get-LocalGroup -SID $sid
                $members = @(Get-LocalGroupMember -Group $group.Name)
                if (@($members | Where-Object {$_.SID.Value -eq $resolved.Value}).Count) { $memberships += $group.Name }
            } catch { Add-Check 'Cuenta' "Lectura grupo $sid" 'ERROR' $_.Exception.Message }
        }
        Add-Check 'Cuenta' 'Grupo local' $(if ($memberships.Count) {'OK'} else {'WARN'}) $(if ($memberships.Count) {$memberships -join '; '} else {'Sin pertenencia directa a Administradores/Power Users. Grupos de dominio anidados requieren revision'})
    } catch { Add-Check 'Cuenta' 'Cuenta de parchado' 'ERROR' ("No se pudo resolver $account (no distingue cuenta inexistente de dominio inaccesible): " + $_.Exception.Message) }
    $searchRoots = @()
    try {
        foreach ($drive in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
            foreach ($folder in @('stage','staging','install','installers','instaladores','software','patches','parches','packages','temp','IBM')) {
                $searchRoots += Join-Path ($drive.DeviceID + '\') $folder
            }
        }
        foreach ($inst in $installs.Values) { $searchRoots += $inst.path; $searchRoots += Split-Path -Parent $inst.path }
        if ($env:TEMP) { $searchRoots += $env:TEMP }
        if ($r.local -and $r.app_folder) { $searchRoots += $r.app_folder }
        Add-Check 'Instalador' 'Alcance de busqueda automatica' 'INFO' ('Raices: ' + (($searchRoots | Sort-Object -Unique) -join '; ') + '. Hasta 3 niveles y 400 carpetas; no se recorren todos los discos ni enlaces.')
        $candidates = @(Find-Fixes $searchRoots)
        foreach ($candidate in $candidates) { Add-Check 'Instalador' 'Candidato encontrado' 'INFO' ("$($candidate.path); version=$($candidate.version)") }
        if (!$candidates.Count) { Add-Check 'Instalador' 'Fix disponible' 'FAIL' 'No se encontro un EXE candidato en el alcance de busqueda. Las validaciones de espacio y entorno se ejecutan igualmente.' }
        else { foreach ($inst in @($installs.Values | Sort-Object path)) { Test-FixCandidates $candidates $inst } }
    } catch { Add-Check 'Instalador' 'Busqueda automatica' 'ERROR' $_.Exception.Message }
    Test-Free 'Sistema C:' 'C:\' $r.min_system_gb
    Test-Free 'TEMP de la sesion' $env:TEMP $r.min_temp_gb 'WARN'
    Add-Check 'Disco' 'Ubicacion TEMP' 'INFO' ("$env:TEMP; corresponde a $($identity.Name), puede diferir de la cuenta de parchado")
    foreach ($selected in @($installs.Values | Sort-Object path)) {
        Test-Free ("Unidad de instalacion: " + $selected.path) $selected.path $r.min_install_gb
        $backup = [IO.Path]::GetPathRoot($selected.path)
        try {
            if (!(Test-Path -LiteralPath $backup -PathType Container)) { throw 'La carpeta de backup debe existir para consultar sus permisos' }
            $size = Get-TreeBytes $selected.path
            Test-Free ("Backup: " + $selected.path) $backup (($size / 1GB) + $r.backup_margin_gb)
        } catch { Add-Check 'Disco' ("Estimacion backup: " + $selected.path) 'ERROR' $_.Exception.Message }
        Test-Acl 'ACL instalacion' $selected.path
        Test-Acl 'ACL destino backup' $backup
    }
    return [pscustomobject]@{server=[string]$r.server; computer=[string]$env:COMPUTERNAME; environment=[string]$r.environment; started=$started; finished=(Get-Date).ToString('o'); checks=@($checks.ToArray())}
}
if ($Library) { return }
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
$ProgressPreference = 'SilentlyContinue'
$r = [Console]::In.ReadToEnd() | ConvertFrom-Json
$session = $null
try {
    if ($r.local) { $result = & $worker $r }
    else {
        $options = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000
        $session = New-PSSession -ComputerName $r.server -Authentication Kerberos -SessionOption $options
        $result = Invoke-Command -Session $session -ScriptBlock $worker -ArgumentList $r
    }
    $result | Select-Object server,computer,environment,started,finished,checks | ConvertTo-Json -Depth 8 -Compress
} catch {
    [pscustomobject]@{server=[string]$r.server; computer=''; environment=[string]$r.environment; started=''; finished=(Get-Date).ToString('o'); checks=@([pscustomobject]@{phase='Ejecucion';name='Consulta local/remota';state='ERROR';detail=$_.Exception.Message})} | ConvertTo-Json -Depth 8 -Compress
} finally { if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue } }
