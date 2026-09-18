$ErrorActionPreference = 'Stop'
$file = Join-Path $PSScriptRoot '..\src\precheck.ps1'
$tokens=$null; $parseErrors=$null
[void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
. $file -Library
. $worker ([pscustomobject]@{helpers_only=$true})
if ((Read-Version 'v6.4.0') -ne [version]'6.4.0.0') { throw 'Normalizacion de version' }
if ($null -ne (Read-Version '6x4x0x5')) { throw 'Version invalida aceptada' }
foreach ($name in @('IBM Connect:Direct','IBM Connect Direct','IBM ConnectDirect v6.4')) {
    if (!(Is-CD $name)) { throw "Discovery no reconoce $name" }
}
if (Is-CD 'IBM MQ') { throw 'Discovery falso positivo' }
$temp = Join-Path ([IO.Path]::GetTempPath()) ('cd-precheck-tests-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    [IO.File]::WriteAllBytes((Join-Path $temp 'sample.bin'),[byte[]](1,2,3))
    if ((Get-TreeBytes $temp) -ne 3) { throw 'Tamano backup incorrecto' }
    $checks.Clear()
    Test-Acl 'Prueba ACL' $temp
    if ($checks.Count -ne 1 -or $checks[0].state -notin @('OK','WARN') -or $checks[0].detail -notmatch 'No prueba acceso efectivo') { throw 'ACL no expone limite de permisos efectivos' }
    $checks.Clear()
    Test-Free 'Prueba disco' 'ruta-relativa-no-valida' 10
    if ($checks.Count -ne 1 -or $checks[0].state -ne 'ERROR') { throw 'Disco inaccesible no marcado ERROR' }
    $checks.Clear()
    Test-Free 'Instalacion sin espacio' $temp 1000000000
    if ($checks[0].state -ne 'FAIL') { throw 'Espacio insuficiente no bloquea el precheck' }
    $checks.Clear()
    Test-Free 'TEMP sin espacio' $temp 1000000000 'WARN'
    if ($checks[0].state -ne 'WARN') { throw 'TEMP no conserva severidad del script original' }
    $fix = Join-Path $temp '6.4.0.5-ConnectDirect-fp0005.exe'
    [IO.File]::WriteAllBytes($fix,[byte[]](1,2,3))
    $candidates = @(Find-Fixes @($temp))
    if ($candidates.Count -ne 1 -or $candidates[0].version -ne [version]'6.4.0.5') { throw 'No descubre el fix sin pedir una ruta al operador' }
    $checks.Clear()
    Test-FixCandidates $candidates ([pscustomobject]@{path='E:\IBM\CD';version='6.4.0.4'})
    if (!@($checks | Where-Object {$_.name -eq 'Version fix > instalada' -and $_.state -eq 'OK'}).Count) { throw 'No selecciona el fix superior' }
    if (!@($checks | Where-Object {$_.name -eq 'Identidad/version por confirmar' -and $_.state -eq 'WARN'}).Count) { throw 'Confia indebidamente en nombre de archivo' }
    $checks.Clear()
    Test-FixCandidates $candidates ([pscustomobject]@{path='E:\IBM\CD';version='6.4.0.5'})
    if (!@($checks | Where-Object {$_.state -eq 'FAIL'}).Count) { throw 'Acepta la misma version' }
    $checks.Clear()
    Test-FixCandidates $candidates ([pscustomobject]@{path='E:\IBM\CD';version='6.3.0.1'})
    if (!@($checks | Where-Object {$_.state -eq 'FAIL'}).Count) { throw 'Acepta distinta rama' }
    [IO.File]::Delete($fix)
} finally {
    if ($fix -and [IO.File]::Exists($fix)) { [IO.File]::Delete($fix) }
    [IO.File]::Delete((Join-Path $temp 'sample.bin'))
    [IO.Directory]::Delete($temp)
}
Write-Output 'OK: sintaxis, discovery, backup, ACL, disco y seleccion automatica del fix'
