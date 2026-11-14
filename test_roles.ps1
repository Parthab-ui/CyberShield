$loginBody = '{"username":"analyst","password":"Analyst@123"}'
$loginRes = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
Write-Host "Analyst Login Success:" $loginRes.success "Role:" $loginRes.user.role
$analystToken = $loginRes.token

# Attempt to delete incident #1 as analyst (should fail with 403 Forbidden)
try {
    Invoke-RestMethod -Uri "http://localhost:8080/api/incidents/1" -Method Delete -Headers @{ Authorization = "Bearer $analystToken" }
    Write-Host "ERROR: Analyst was able to delete incident!"
} catch {
    Write-Host "SUCCESS: Role Authorization correctly enforced! Analyst deletion blocked with status:" $_.Exception.Response.StatusCode.value__
}
