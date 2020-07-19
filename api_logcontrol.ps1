Import-Module Pode

Start-PodeServer -Threads 2 {

    Add-PodeEndpoint -Address * -Port 9081 -Protocol Http

    # New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging
    New-PodeLoggingMethod -Terminal | Enable-PodeRequestLogging

    $env:HostIP = (
        Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4DefaultGateway -ne $null -and
            $_.NetAdapter.Status -ne "Disconnected"
        }
    ).IPv4Address.IPAddress

    # STATUS
    Add-PodeRoute -Method Get -Path '/api/logcontrol/status' -ScriptBlock {
        Write-PodeJsonResponse -Value @{ 
            'api'      = 'Log Control'
            'status'   = 'OK'
            'version'  = '1.0'
            'datetime' = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'status')
            ))
    }

    # TRACE
    Add-PodeRoute -Method Post -Path '/api/logcontrol/trace/:serviceName' -ScriptBlock {
        param($e)

        $serviceName = $e.Parameters['serviceName']
        $searchString = '\\' + $serviceName + '\\log\\202'
        $filePath = "C:\tools\promtail\promtail.yml"
        $promtailRef = "C:\tools\promtail\NLog.config.TRACE.REF"
        
        $test = $((Select-String -Pattern $searchString $filePath | Select-Object -expand line).Split(" ") | Select-Object -Last 1)
        $test = $test.Substring(0, $test.Length - 13)
        Copy-Item -Path $promtailRef -Destination "$test\NLog.config"
        Start-Sleep 2
        ((Get-Content -Path "$test\NLog.config" -Raw) -replace 'logfile', 'logfile') | Set-Content -Path "$test\NLog.config"
    
        Write-PodeJsonResponse -Value @{
            service  = $e.Parameters['serviceName']
            level    = "trace"
            path     = "$test\NLog.config"
            hostname = "$env:COMPUTERNAME"
            address  = "$env:HostIP"
            datetime = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'serviceName')
            ))
    }

    # DEBUG
    Add-PodeRoute -Method Post -Path '/api/logcontrol/debug/:serviceName' -ScriptBlock {
        param($e)
        
        $serviceName = $e.Parameters['serviceName']
        $searchString = '\\' + $serviceName + '\\log\\202'
        $filePath = "C:\tools\promtail\promtail.yml"
        $promtailRef = "C:\tools\promtail\NLog.config.DEBUG.REF"
        
        $test = $((Select-String -Pattern $searchString $filePath | Select-Object -expand line).Split(" ") | Select-Object -Last 1)
        $test = $test.Substring(0, $test.Length - 13)
        Copy-Item -Path $promtailRef -Destination "$test\NLog.config"
        Start-Sleep 2
        ((Get-Content -Path "$test\NLog.config" -Raw) -replace 'logfile', 'logfile') | Set-Content -Path "$test\NLog.config"
    
        Write-PodeJsonResponse -Value @{
            service  = $e.Parameters['serviceName']
            level    = "debug"
            path     = "$test\NLog.config"
            hostname = "$env:COMPUTERNAME"
            address  = "$env:HostIP"
            datetime = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'serviceName')
            ))
    }

    # INFO
    Add-PodeRoute -Method Post -Path '/api/logcontrol/info/:serviceName' -ScriptBlock {
        param($e)

        $serviceName = $e.Parameters['serviceName']
        $searchString = '\\' + $serviceName + '\\log\\202'
        $filePath = "C:\tools\promtail\promtail.yml"
        $promtailRef = "C:\tools\promtail\NLog.config.INFO.REF"
        
        $test = $((Select-String -Pattern $searchString $filePath | Select-Object -expand line).Split(" ") | Select-Object -Last 1)
        $test = $test.Substring(0, $test.Length - 13)
        Copy-Item -Path $promtailRef -Destination "$test\NLog.config"
        Start-Sleep 2
        ((Get-Content -Path "$test\NLog.config" -Raw) -replace 'logfile', 'logfile') | Set-Content -Path "$test\NLog.config"
    
        Write-PodeJsonResponse -Value @{
            service  = $e.Parameters['serviceName']
            level    = "info"
            path     = "$test\NLog.config"
            hostname = "$env:COMPUTERNAME"
            address  = "$env:HostIP"
            datetime = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'serviceName')
            ))
    }

    # WARN
    Add-PodeRoute -Method Post -Path '/api/logcontrol/warn/:serviceName' -ScriptBlock {
        param($e)

        $serviceName = $e.Parameters['serviceName']
        $searchString = '\\' + $serviceName + '\\log\\202'
        $filePath = "C:\tools\promtail\promtail.yml"
        $promtailRef = "C:\tools\promtail\NLog.config.WARN.REF"
        
        $test = $((Select-String -Pattern $searchString $filePath | Select-Object -expand line).Split(" ") | Select-Object -Last 1)
        $test = $test.Substring(0, $test.Length - 13)
        Copy-Item -Path $promtailRef -Destination "$test\NLog.config"
        Start-Sleep 2
        ((Get-Content -Path "$test\NLog.config" -Raw) -replace 'logfile', 'logfile') | Set-Content -Path "$test\NLog.config"
    
        Write-PodeJsonResponse -Value @{
            service  = $e.Parameters['serviceName']
            level    = "warn"
            path     = "$test\NLog.config"
            hostname = "$env:COMPUTERNAME"
            address  = "$env:HostIP"
            datetime = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'serviceName')
            ))
    }

    # ERROR
    Add-PodeRoute -Method Post -Path '/api/logcontrol/error/:serviceName' -ScriptBlock {
        param($e)

        $serviceName = $e.Parameters['serviceName']
        $searchString = '\\' + $serviceName + '\\log\\202'
        $filePath = "C:\tools\promtail\promtail.yml"
        $promtailRef = "C:\tools\promtail\NLog.config.ERROR.REF"
        
        $test = $((Select-String -Pattern $searchString $filePath | Select-Object -expand line).Split(" ") | Select-Object -Last 1)
        $test = $test.Substring(0, $test.Length - 13)
        Copy-Item -Path $promtailRef -Destination "$test\NLog.config"
        Start-Sleep 2
        ((Get-Content -Path "$test\NLog.config" -Raw) -replace 'logfile', 'logfile') | Set-Content -Path "$test\NLog.config"
    
        Write-PodeJsonResponse -Value @{
            service  = $e.Parameters['serviceName']
            level    = "error"
            path     = "$test\NLog.config"
            hostname = "$env:COMPUTERNAME"
            address  = "$env:HostIP"
            datetime = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'serviceName')
            ))
    }

    # FATAL
    Add-PodeRoute -Method Post -Path '/api/logcontrol/fatal/:serviceName' -ScriptBlock {
        param($e)

        $serviceName = $e.Parameters['serviceName']
        $searchString = '\\' + $serviceName + '\\log\\202'
        $filePath = "C:\tools\promtail\promtail.yml"
        $promtailRef = "C:\tools\promtail\NLog.config.FATAL.REF"
        
        $test = $((Select-String -Pattern $searchString $filePath | Select-Object -expand line).Split(" ") | Select-Object -Last 1)
        $test = $test.Substring(0, $test.Length - 13)
        Copy-Item -Path $promtailRef -Destination "$test\NLog.config"
        Start-Sleep 2
        ((Get-Content -Path "$test\NLog.config" -Raw) -replace 'logfile', 'logfile') | Set-Content -Path "$test\NLog.config"
    
        Write-PodeJsonResponse -Value @{
            service  = $e.Parameters['serviceName']
            level    = "fatal"
            path     = "$test\NLog.config"
            hostname = "$env:COMPUTERNAME"
            address  = "$env:HostIP"
            datetime = "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss');)"
        }
    } -PassThru | Add-PodeOAResponse -StatusCode 200 -Description 'Log Control' -ContentSchemas @{
        'application/json' = (New-PodeOAObjectProperty -Properties @(
                (New-PodeOAIntProperty -Name 'serviceName')
            ))
    }
   
}
