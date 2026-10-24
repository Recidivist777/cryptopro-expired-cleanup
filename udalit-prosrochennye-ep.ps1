<#
.SYNOPSIS
  Удаляет просроченные электронные подписи: сертификаты из хранилища Windows
  и (с ключом -Containers) контейнеры закрытых ключей КриптоПро на любых носителях.

.DESCRIPTION
  Без ключа -Delete скрипт ничего не удаляет, только показывает, что нашёл.

  Сертификаты: проверяется хранилище "Личное" текущего пользователя
  (с -AllUsers — ещё и хранилище компьютера).

  Контейнеры (-Containers): через утилиты КриптоПро (csptest, certmgr) перебираются
  все контейнеры, которые видит КриптоПро: реестр, диск (HDIMAGE), папки на дисках
  и флешках (FAT12_X), токены (Рутокен, JaCarta и др.). Из каждого контейнера
  достаётся сертификат и проверяется срок. Контейнер удаляется, только если:
    - в нём есть сертификат и срок этого сертификата истёк;
    - этот же ключ не используется действующим сертификатом;
    - удалось сделать резервную копию контейнера (кроме токенов, с них копию
      снять нельзя; обойти это требование можно ключом -Force).

  Копии сертификатов (.cer), папок контейнеров и веток реестра сохраняются
  в папку "Просроченные ЭП <дата>" на рабочем столе.

.PARAMETER Delete
  Удалить найденное (после подтверждения).

.PARAMETER Containers
  Искать и удалять также контейнеры закрытых ключей КриптоПро.

.PARAMETER AllUsers
  Проверять также хранилище сертификатов компьютера. Нужен запуск от администратора.

.PARAMETER Force
  Удалять контейнер, даже если не удалось сделать его копию.

.PARAMETER Yes
  Не спрашивать подтверждение.

.EXAMPLE
  .\udalit-prosrochennye-ep.ps1 -Containers
  Только показать просроченные сертификаты и контейнеры.

.EXAMPLE
  .\udalit-prosrochennye-ep.ps1 -Delete -Containers
  Удалить просроченные сертификаты и контейнеры (после подтверждения).
#>
param(
    [switch]$Delete,
    [switch]$Containers,
    [switch]$AllUsers,
    [switch]$Force,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$now = Get-Date

# ======================= Вспомогательные функции =======================

function Get-SimpleName($cert, [bool]$issuer) {
    $n = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $issuer)
    if ([string]::IsNullOrWhiteSpace($n)) { return $cert.Subject }
    return $n
}

function Get-SafeName([string]$s) {
    $s = $s -replace '[\\/:*?"<>|]', '_'
    if ($s.Length -gt 80) { $s = $s.Substring(0, 80) }
    return $s
}

# Запуск внешней утилиты с перехватом вывода.
# Вывод утилит КриптоПро бывает в кодировке 866 или 1251 — выбираем ту,
# при которой получается больше русских букв.
function Invoke-Tool([string]$exe, [string]$arguments) {
    $latin = [Text.Encoding]::GetEncoding(28591)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = $arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $latin
    $psi.StandardErrorEncoding = $latin
    $p = [System.Diagnostics.Process]::Start($psi)
    $errTask = $p.StandardError.ReadToEndAsync()
    $out = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
    $raw = $latin.GetBytes($out + $errTask.Result)

    $best = ''; $bestScore = -1
    foreach ($cp in 866, 1251) {
        $text = [Text.Encoding]::GetEncoding($cp).GetString($raw)
        $score = ([regex]::Matches($text, '[А-яЁё]')).Count
        if ($score -gt $bestScore) { $best = $text; $bestScore = $score }
    }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $best }
}

function Find-Bytes([byte[]]$hay, [byte[]]$needle) {
    for ($i = 0; $i -le $hay.Length - $needle.Length; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $needle.Length; $j++) {
            if ($hay[$i + $j] -ne $needle[$j]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    return $false
}

# В файле name.key папки контейнера записано имя контейнера (строка ASN.1).
# Ищем точное совпадение: тег строки + длина + само имя.
function Test-NameKey([string]$file, [string]$name) {
    try { $data = [IO.File]::ReadAllBytes($file) } catch { return $false }
    foreach ($enc in @([Text.Encoding]::UTF8, [Text.Encoding]::GetEncoding(1251))) {
        $nb = $enc.GetBytes($name)
        if ($nb.Length -gt 127) { continue }
        foreach ($tag in 0x16, 0x0C, 0x13) {
            $pattern = [byte[]](@([byte]$tag, [byte]$nb.Length) + $nb)
            if (Find-Bytes $data $pattern) { return $true }
        }
    }
    return $false
}

function Find-ContainerFolder([string[]]$roots, [int]$depth, [string]$name) {
    foreach ($root in $roots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
        $keys = Get-ChildItem -LiteralPath $root -Recurse -Depth $depth -Filter 'name.key' -File -Force -ErrorAction SilentlyContinue
        foreach ($k in $keys) {
            if (Test-NameKey $k.FullName $name) { return $k.Directory.FullName }
        }
    }
    return $null
}

function Get-StorageLabel([string]$reader) {
    if ($reader -eq 'REGISTRY') { return 'Реестр' }
    if ($reader -eq 'HDIMAGE') { return 'Диск (HDIMAGE)' }
    if ($reader -match '^FAT12_([A-Za-z])$') { return "Папка на диске $($Matches[1].ToUpper()):" }
    return "Токен: $reader"
}

function Test-IsToken([string]$reader) {
    return -not ($reader -eq 'REGISTRY' -or $reader -eq 'HDIMAGE' -or $reader -match '^FAT12_[A-Za-z]$')
}

# Резервная копия контейнера.
# Возвращает объект: Copy — путь к копии, Folder — папка контейнера на диске,
# RegKey — ветка реестра контейнера. Или $null, если копию сделать не удалось.
function Backup-Container($c, [string]$dir) {
    if ($c.Reader -eq 'REGISTRY') {
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $file = Join-Path $dir ("Реестр_" + (Get-SafeName $c.Name) + ".reg")
        foreach ($root in 'HKLM\SOFTWARE\WOW6432Node\Crypto Pro\Settings\Users',
                          'HKLM\SOFTWARE\Crypto Pro\Settings\Users') {
            $key = "$root\$sid\Keys\$($c.Name)"
            $r = Invoke-Tool "$env:SystemRoot\System32\reg.exe" ('export "{0}" "{1}" /y' -f $key, $file)
            if ($r.ExitCode -eq 0 -and (Test-Path -LiteralPath $file)) {
                return [pscustomobject]@{ Copy = $file; Folder = $null; RegKey = $key }
            }
        }
        return $null
    }

    $folder = $null
    if ($c.Reader -match '^FAT12_([A-Za-z])$') {
        $folder = Find-ContainerFolder @("$($Matches[1]):\") 3 $c.Name
    } elseif ($c.Reader -eq 'HDIMAGE') {
        $roots = @("$env:LOCALAPPDATA\Crypto Pro", "$env:APPDATA\Crypto Pro", "$env:ProgramData\Crypto Pro")
        $folder = Find-ContainerFolder $roots 4 $c.Name
    }
    if (-not $folder) { return $null }

    $dest = Join-Path $dir ((Get-SafeName $c.Reader) + "_" + (Split-Path $folder -Leaf))
    try {
        Copy-Item -LiteralPath $folder -Destination $dest -Recurse -Force
        return [pscustomobject]@{ Copy = $dest; Folder = $folder; RegKey = $null }
    } catch {
        return $null
    }
}

# Удаление контейнера средствами КриптоПро.
# Ключи ГОСТ 2012 открываются только провайдером своего типа (80 — 256 бит,
# 81 — 512 бит), поэтому перебираем типы. Возвращает $true или текст ошибки.
function Remove-ContainerCsp([string]$csptest, [string]$fqcn) {
    $lastMsg = ''
    foreach ($pt in '80', '81', '75', '') {
        $cmd = '-keyset -deletekeyset -container "{0}"' -f $fqcn
        if ($pt) { $cmd += " -provtype $pt" }
        $r = Invoke-Tool $csptest $cmd
        if ($r.ExitCode -eq 0) { return $true }
        $lastMsg = ($r.Output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
    }
    return [string]$lastMsg
}

# ---------- Пустые папки от удалённых контейнеров ----------

$script:HdImageRoots = @("$env:LOCALAPPDATA\Crypto Pro", "$env:APPDATA\Crypto Pro", "$env:ProgramData\Crypto Pro")

function Test-EmptyDir([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { return $false }
    $items = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue)
    return $items.Count -eq 0
}

# Папки, которые никогда не удаляем, даже пустые
function Test-ProtectedDir([string]$path) {
    $p = $path.TrimEnd('\')
    if ($p -match '^[A-Za-z]:$') { return $true }                       # корень диска
    foreach ($r in $script:HdImageRoots) { if ($r -and $p -ieq $r.TrimEnd('\')) { return $true } }
    $prof = $env:USERPROFILE.TrimEnd('\')
    if ($p -ieq $prof) { return $true }
    if ((Split-Path $p -Parent) -ieq $prof) { return $true }        # Рабочий стол, Документы и т.п.
    return $false
}

# Удаляет пустую папку и поднимается вверх, пока родители тоже пустые (не выше $levels).
# Возвращает список удалённых папок.
function Remove-EmptyDirUp([string]$path, [int]$levels) {
    $removed = @()
    $cur = $path
    for ($i = 0; $i -le $levels; $i++) {
        if (-not $cur -or (Test-ProtectedDir $cur) -or -not (Test-EmptyDir $cur)) { break }
        try {
            Remove-Item -LiteralPath $cur -Force
            $removed += $cur
        } catch { break }
        $cur = Split-Path $cur -Parent
    }
    return $removed
}

# Ищет пустые папки, оставшиеся от контейнеров, на всех дисках и флешках.
# Имена контейнеров бывают двух видов: "что-то.000" и просто число ("2560", "3072").
# Числовые имена ищем только не на системном диске — там пустые числовые папки бывают у программ.
function Find-EmptyContainerDirs {
    $found = @()
    $roots = @()
    $sysDrive = ($env:SystemDrive.TrimEnd('\') + '\')
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        if ($d.IsReady -and ($d.DriveType -eq 'Fixed' -or $d.DriveType -eq 'Removable')) {
            $isSys = ($d.RootDirectory.FullName -ieq $sysDrive)
            $roots += [pscustomobject]@{ Path = $d.RootDirectory.FullName; Depth = 3; Numeric = -not $isSys }
        }
    }
    foreach ($r in $script:HdImageRoots) {
        if ($r) { $roots += [pscustomobject]@{ Path = $r; Depth = 4; Numeric = $true } }
    }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root.Path)) { continue }
        $numeric = $root.Numeric
        $dirs = Get-ChildItem -LiteralPath $root.Path -Directory -Recurse -Depth $root.Depth -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch '\\(\$RECYCLE\.BIN|System Volume Information)(\\|$)' -and
                ($_.Name -match '\.\d{3}$' -or ($numeric -and $_.Name -match '^\d+$'))
            }
        foreach ($dir in $dirs) {
            if (Test-EmptyDir $dir.FullName) { $found += $dir.FullName }
        }
    }
    return @($found | Select-Object -Unique)
}

# ======================= Сертификаты в хранилище =======================

$stores = @('Cert:\CurrentUser\My')
if ($AllUsers) { $stores += 'Cert:\LocalMachine\My' }

$allStoreCerts = @()
foreach ($store in $stores) {
    try {
        $allStoreCerts += Get-ChildItem -Path $store
    } catch {
        Write-Warning "Не удалось открыть хранилище $store : $($_.Exception.Message)"
    }
}
$expiredCerts = @($allStoreCerts | Where-Object { $_.NotAfter -lt $now })

# Открытые ключи действующих сертификатов — такие контейнеры не трогаем
$validKeys = @{}
foreach ($vc in ($allStoreCerts | Where-Object { $_.NotAfter -ge $now })) {
    $validKeys[$vc.GetPublicKeyString()] = $true
}

# ======================= Контейнеры КриптоПро =======================

$expiredConts = @()
$emptyDirs = @()
$csptest = $null; $certmgr = $null

if ($Containers) {
    foreach ($d in @("$env:ProgramFiles\Crypto Pro\CSP", "${env:ProgramFiles(x86)}\Crypto Pro\CSP")) {
        if ($d -and (Test-Path -LiteralPath (Join-Path $d 'csptest.exe'))) {
            $csptest = Join-Path $d 'csptest.exe'
            $certmgr = Join-Path $d 'certmgr.exe'
            break
        }
    }

    if (-not $csptest) {
        Write-Warning "КриптоПро CSP не найден (нет csptest.exe). Контейнеры проверить нельзя."
    } else {
        Write-Host "Ищу контейнеры КриптоПро на всех носителях (может занять минуту)..." -ForegroundColor Cyan
        $r = Invoke-Tool $csptest '-keyset -enum_cont -fqcn -verifyc'
        $fqcns = @($r.Output -split "`r?`n" |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -like '\\.\*' } |
            Select-Object -Unique)

        $checked = 0
        foreach ($f in $fqcns) {
            if ($f -notmatch '^\\\\\.\\([^\\]+)\\(.+)$') { continue }
            $reader = $Matches[1]; $short = $Matches[2]
            $checked++

            $tmp = Join-Path $env:TEMP ("ep_" + [guid]::NewGuid().ToString('N') + ".cer")
            $cert = $null
            try {
                $null = Invoke-Tool $certmgr ('-export -container "{0}" -dest "{1}"' -f $f, $tmp)
                if (Test-Path -LiteralPath $tmp) {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $tmp
                }
            } catch {
                $cert = $null
            } finally {
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
            }

            if (-not $cert) {
                Write-Host "  Пропуск: $f — в контейнере нет сертификата или он не читается" -ForegroundColor DarkGray
                continue
            }
            if ($cert.NotAfter -ge $now) { continue }

            $action = 'удалить'
            if ($validKeys.ContainsKey($cert.GetPublicKeyString())) {
                $action = 'пропуск: ключ нужен действующему сертификату'
            }

            $expiredConts += [pscustomobject]@{
                FQCN    = $f
                Reader  = $reader
                Name    = $short
                Cert    = $cert
                Owner   = Get-SimpleName $cert $false
                Action  = $action
            }
        }
        Write-Host "Проверено контейнеров: $checked, просроченных: $($expiredConts.Count)"
    }

    Write-Host "Ищу пустые папки от удалённых контейнеров..." -ForegroundColor Cyan
    $emptyDirs = @(Find-EmptyContainerDirs)
}

# ======================= Отчёт =======================

if ($expiredCerts.Count -eq 0 -and $expiredConts.Count -eq 0 -and $emptyDirs.Count -eq 0) {
    Write-Host "Просроченных подписей не найдено." -ForegroundColor Green
    return
}

if ($expiredCerts.Count -gt 0) {
    Write-Host ""
    Write-Host "Просроченные сертификаты в хранилище Windows: $($expiredCerts.Count)" -ForegroundColor Yellow
    $expiredCerts | Sort-Object NotAfter | ForEach-Object {
        [pscustomobject]@{
            'Владелец'      = Get-SimpleName $_ $false
            'Кем выдан'     = Get-SimpleName $_ $true
            'Действовал до' = $_.NotAfter.ToString('dd.MM.yyyy')
            'Хранилище'     = ($_.PSParentPath -split '::')[-1]
            'Отпечаток'     = $_.Thumbprint
        }
    } | Format-Table -AutoSize -Wrap
}

if ($expiredConts.Count -gt 0) {
    Write-Host ""
    Write-Host "Контейнеры ключей с просроченными сертификатами: $($expiredConts.Count)" -ForegroundColor Yellow
    $expiredConts | Sort-Object { $_.Cert.NotAfter } | ForEach-Object {
        [pscustomobject]@{
            'Носитель'      = Get-StorageLabel $_.Reader
            'Контейнер'     = $_.Name
            'Владелец'      = $_.Owner
            'Действовал до' = $_.Cert.NotAfter.ToString('dd.MM.yyyy')
            'Действие'      = $_.Action
        }
    } | Format-Table -AutoSize -Wrap
}

if ($emptyDirs.Count -gt 0) {
    Write-Host ""
    Write-Host "Пустые папки от удалённых контейнеров: $($emptyDirs.Count)" -ForegroundColor Yellow
    $emptyDirs | ForEach-Object { Write-Host "  $_" }
}

if (-not $Delete) {
    Write-Host "Это был просмотр, ничего не удалено." -ForegroundColor Cyan
    Write-Host "Чтобы удалить, запустите скрипт с ключом -Delete"
    return
}

$toDeleteConts = @($expiredConts | Where-Object { $_.Action -eq 'удалить' })

if ($expiredCerts.Count -eq 0 -and $toDeleteConts.Count -eq 0 -and $emptyDirs.Count -eq 0) {
    Write-Host "Удалять нечего." -ForegroundColor Green
    return
}

if (-not $Yes) {
    Write-Host ""
    if ($toDeleteConts.Count -gt 0) {
        Write-Host "ВНИМАНИЕ: удаление контейнеров уничтожает закрытые ключи. С токенов копию снять нельзя." -ForegroundColor Red
    }
    $q = "Удалить сертификатов: $($expiredCerts.Count), контейнеров: $($toDeleteConts.Count), пустых папок: $($emptyDirs.Count)? Введите 'да'"
    $answer = Read-Host $q
    if ($answer -notin @('да', 'Да', 'ДА', 'y', 'yes')) {
        Write-Host "Отменено." -ForegroundColor Cyan
        return
    }
}

$backupDir = Join-Path ([Environment]::GetFolderPath('Desktop')) ("Просроченные ЭП " + $now.ToString('yyyy-MM-dd_HH-mm'))
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

function Save-CertCopy($cert, [string]$dir) {
    $file = Join-Path $dir ("{0}_до_{1}_{2}.cer" -f (Get-SafeName (Get-SimpleName $cert $false)),
        $cert.NotAfter.ToString('yyyy-MM-dd'), $cert.Thumbprint.Substring(0, 8))
    try {
        [IO.File]::WriteAllBytes($file, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    } catch {
        Write-Warning "Не удалось сохранить копию сертификата: $($_.Exception.Message)"
    }
}

# ---------- Удаление контейнеров ----------
$contOk = 0; $contFail = 0; $contSkip = 0
$script:dirsRemoved = @()
foreach ($c in $toDeleteConts) {
    $label = "$(Get-StorageLabel $c.Reader) \ $($c.Name) ($($c.Owner))"
    Save-CertCopy $c.Cert $backupDir

    $backup = $null
    if (Test-IsToken $c.Reader) {
        Write-Host "Токен — копию контейнера снять нельзя: $label" -ForegroundColor DarkYellow
    } else {
        $backup = Backup-Container $c $backupDir
        if (-not $backup) {
            if ($Force) {
                Write-Host "Копию сделать не удалось, удаляю (указан -Force): $label" -ForegroundColor DarkYellow
            } else {
                Write-Host "Пропуск — не удалось сделать копию (можно запустить с -Force): $label" -ForegroundColor DarkYellow
                $contSkip++
                continue
            }
        }
    }

    # 1) Штатно, через КриптоПро
    $res = Remove-ContainerCsp $csptest $c.FQCN
    if ($res -eq $true) {
        Write-Host "Контейнер удалён: $label" -ForegroundColor Green
        $contOk++
        # КриптоПро удаляет файлы ключа, а пустую папку оставляет — убираем её
        if ($backup -and $backup.Folder) {
            $script:dirsRemoved += @(Remove-EmptyDirUp $backup.Folder 2)
        }
        continue
    }

    # 2) КриптоПро отказал — удаляем напрямую то, с чего уже снята копия
    $done = $false
    if ($backup -and $backup.Folder) {
        try {
            Remove-Item -LiteralPath $backup.Folder -Recurse -Force
            $done = -not (Test-Path -LiteralPath $backup.Folder)
            if ($done) { $script:dirsRemoved += @(Remove-EmptyDirUp (Split-Path $backup.Folder -Parent) 1) }
        } catch { $res = $_.Exception.Message }
    } elseif ($backup -and $backup.RegKey) {
        $r = Invoke-Tool "$env:SystemRoot\System32\reg.exe" ('delete "{0}" /f' -f $backup.RegKey)
        $done = ($r.ExitCode -eq 0)
        if (-not $done) { $res = $r.Output.Trim() }
    }

    if ($done) {
        Write-Host "Контейнер удалён (напрямую, копия сохранена): $label" -ForegroundColor Green
        $contOk++
    } else {
        Write-Host "Ошибка удаления контейнера: $label — $res" -ForegroundColor Red
        $contFail++
    }
}

# ---------- Пустые папки, оставшиеся от прошлых удалений ----------
foreach ($d in $emptyDirs) {
    $script:dirsRemoved += @(Remove-EmptyDirUp $d 2)
}
foreach ($d in ($script:dirsRemoved | Select-Object -Unique)) {
    Write-Host "Пустая папка удалена: $d" -ForegroundColor Green
}

# ---------- Удаление сертификатов из хранилища ----------
$certOk = 0; $certFail = 0
foreach ($c in $expiredCerts) {
    $name = Get-SimpleName $c $false
    Save-CertCopy $c $backupDir
    try {
        Remove-Item -Path $c.PSPath
        Write-Host "Сертификат удалён: $name (до $($c.NotAfter.ToString('dd.MM.yyyy')))" -ForegroundColor Green
        $certOk++
    } catch {
        Write-Host "Ошибка: $name — $($_.Exception.Message)" -ForegroundColor Red
        $certFail++
    }
}

Write-Host ""
Write-Host "Готово." -ForegroundColor Yellow
Write-Host "  Сертификаты: удалено $certOk, ошибок $certFail"
if ($Containers) {
    Write-Host "  Контейнеры:  удалено $contOk, ошибок $contFail, пропущено $contSkip"
    Write-Host "  Пустые папки: удалено $(@($script:dirsRemoved | Select-Object -Unique).Count)"
}
Write-Host "Копии сохранены в: $backupDir"
