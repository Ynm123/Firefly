# Node 的 fetch（undici）不会自动读取 Windows 系统代理，
# 而 Astro 构建字体时需要从 cdn.jsdelivr.net 下载 woff2 计算字体度量，
# 直连失败会报 CannotFetchFontFile 并中断 dev。这里先探测系统代理注入给 Node。
if ($env:HTTP_PROXY -or $env:HTTPS_PROXY) {
	# 已有代理环境变量时，只需让 Node 24+ 读取它们
	$env:NODE_USE_ENV_PROXY = '1'
}
else {
	$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
	if ($inet.ProxyEnable -eq 1 -and $inet.ProxyServer) {
		$proxy = $inet.ProxyServer
		if ($proxy -notmatch '^https?://') { $proxy = "http://$proxy" }
		$env:HTTP_PROXY = $proxy
		$env:HTTPS_PROXY = $proxy
		$env:NODE_USE_ENV_PROXY = '1'
		Write-Host "已启用系统代理：$proxy" -ForegroundColor DarkGray
	}
}

pnpm install
pnpm run dev

# 保持窗口打开，方便查看输出
Read-Host "按回车键退出..."