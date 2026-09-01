$files = Get-ChildItem -LiteralPath 'D:\RAG HACK' -Recurse -Force -File
$files | Group-Object Extension | Sort-Object { ($_.Group | Measure-Object Length -Sum).Sum } -Descending | Select-Object @{N='Extension';E={if($_.Name){$_.Name}else{'(no ext)'}}}, Count, @{N='SizeGB';E={[math]::Round(($_.Group | Measure-Object Length -Sum).Sum/1GB,2)}} | Format-Table -AutoSize
Write-Host '---TOTAL---'
$total = ($files | Measure-Object Length -Sum).Sum
Write-Host ('Total Files: ' + $files.Count)
Write-Host ('Total Size GB: ' + [math]::Round($total/1GB,2))