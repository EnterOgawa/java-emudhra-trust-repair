# ファイル: build.ps1 / バージョン: 01.00.00
# 作成日: 2026/10/26 / 制作者: Shunji Ogawa
# Copyright (c) 2026 EnterSystem CO.,LTD.
# SPDX-License-Identifier: Apache-2.0
# 更新履歴: Ver.01.00.00 Shunji Ogawa 2026/10/26 通常releaseをoutputへ配置。
# Cargo内部のcacheはtarget側に保持し、受渡しexeと許諾だけをoutputへ出力する。
$ErrorActionPreference = 'Stop'
$temporaryExe = $null
Push-Location -LiteralPath $PSScriptRoot
try {
	# 必要な許諾を先に確認し、不足した配布物を作らない。
	$licenseFiles = @(
		@{ Source = 'LICENSE'; Destination = 'LICENSE' },
		@{ Source = 'assets/OFL-NotoSansJP.txt'; Destination = 'licenses/OFL-NotoSansJP.txt' },
		@{ Source = 'licenses/egui-emoji-icon-font-mit-license.txt'; Destination = 'licenses/egui-emoji-icon-font-mit-license.txt' },
		@{ Source = 'licenses/egui-Hack-Regular.txt'; Destination = 'licenses/egui-Hack-Regular.txt' },
		@{ Source = 'licenses/egui-OFL.txt'; Destination = 'licenses/egui-OFL.txt' },
		@{ Source = 'licenses/egui-UFL.txt'; Destination = 'licenses/egui-UFL.txt' }
	)
	foreach ($license in $licenseFiles) {
		if (-not (Test-Path -LiteralPath $license.Source -PathType Leaf)) {
			throw "Missing required license: $($license.Source)"
		}
	}

	# 今回のbuildが報告した実exeを使い、CARGO_TARGET_DIR変更時の古いexe選択を防ぐ。
	$artifacts = @(& cargo build --release --locked -p trust_repair_app --target x86_64-pc-windows-msvc --message-format=json-render-diagnostics | ForEach-Object {
		$message = $_ | ConvertFrom-Json
		if ($message.reason -eq 'compiler-message') {
			# JSONに含まれる診断文を表示し、build失敗の理由を隠さない。
			Write-Host -NoNewline $message.message.rendered
		} elseif ($message.reason -eq 'compiler-artifact' -and $message.target.name -eq 'java-trust-repair' -and $message.executable) {
			$message
		}
	})
	if ($LASTEXITCODE -ne 0) { throw "Cargo build failed (exit $LASTEXITCODE). output was not updated." }
	if ($artifacts.Count -ne 1 -or -not (Test-Path -LiteralPath $artifacts[0].executable -PathType Leaf)) {
		throw 'Cargo did not report exactly one application executable. output was not updated.'
	}
	$builtExe = $artifacts[0].executable
	$outputDirectory = Join-Path $PSScriptRoot 'output'
	$destinationExe = Join-Path $outputDirectory 'JavaTrustRepair.exe'
	New-Item -ItemType Directory -Path (Join-Path $outputDirectory 'licenses') -Force | Out-Null
	$temporaryExe = Join-Path $outputDirectory ('.JavaTrustRepair-' + [Guid]::NewGuid().ToString('N') + '.tmp')
	Copy-Item -LiteralPath $builtExe -Destination $temporaryExe
	foreach ($license in $licenseFiles) {
		Copy-Item -LiteralPath $license.Source -Destination (Join-Path $outputDirectory $license.Destination) -Force
	}

	# 既存exeは原子的に置換する。使用中などで失敗しても既存exeを保持し、強制終了しない。
	try {
		if (Test-Path -LiteralPath $destinationExe) {
			[IO.File]::Replace($temporaryExe, $destinationExe, [NullString]::Value)
		} else {
			[IO.File]::Move($temporaryExe, $destinationExe)
		}
	} catch {
		throw "Could not update output/JavaTrustRepair.exe. The existing executable was kept. Close it yourself if it is running, then retry. $($_.Exception.Message)"
	}
	Write-Host "Built: $destinationExe"
	Write-Host "SHA-256: $((Get-FileHash -LiteralPath $destinationExe -Algorithm SHA256).Hash)"
} finally {
	# この実行が作成した一時ファイルだけを後始末する。
	if ($temporaryExe -and (Test-Path -LiteralPath $temporaryExe)) {
		Remove-Item -LiteralPath $temporaryExe -Force
	}
	Pop-Location
}
