param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Executable,

    [Parameter(ValueFromRemainingArguments = $true, Position = 1)]
    [string[]]$Arguments
)

& $Executable @Arguments
exit $LASTEXITCODE
