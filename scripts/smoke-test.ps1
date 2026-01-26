Write-Host "Generating sample network traffic..."
$urls = @(
  "https://www.microsoft.com",
  "https://www.bing.com",
  "https://www.github.com"
)

foreach ($url in $urls) {
  try {
    Invoke-WebRequest -Uri $url -UseBasicParsing | Out-Null
    Write-Host "Fetched $url"
  } catch {
    Write-Warning "Failed to fetch $url: $($_.Exception.Message)"
  }
}

Write-Host "Done. Run the tool in another terminal to observe events."
