$comp = "az-kf02-wc112"
     

Invoke-Command -ComputerName $comp -ScriptBlock {
    #wpr trace
    cd C:\windows\system32
    .\wpr.exe -start D:\temp\HyperVTraceProfile.wprp!AllHypTraces -filemode -recordtempto D:\temp
}


Invoke-Command -ComputerName $comp -ScriptBlock {
    #wpr trace
    cd C:\windows\system32
    .\wpr.exe -stop D:\temp\hypervtrace.etl
}

