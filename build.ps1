# 打包成免安装的 Windows 版本：dist\XSS扫描器\ 整个目录复制给别人，双击 XSS扫描器.exe 即可
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

pyinstaller --noconfirm --onedir --noconsole --name "XSS扫描器" `
    --add-data "page.html;." --distpath dist --workpath build webapp.py

Compress-Archive -Path "dist\XSS扫描器\*" -DestinationPath "dist\XSS-scanner-windows-x64.zip" -Force
Write-Host "打包完成：dist\XSS-scanner-windows-x64.zip"
