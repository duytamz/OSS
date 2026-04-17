rule Suspicous_Python_Execution {
    meta:
        description = "Detects dynamic execution of code which is common in supply chain attacks"
        severity = "High"
    strings:
        $eval = "eval("
        $exec = "exec("
        $b64decode = "base64.b64decode"
        $os_system = "os.system"
    condition:
        any of them
}