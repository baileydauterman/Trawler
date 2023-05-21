class Detector {
    [Detection]$CurrentDetection

    [bool] StartUp() {
        throw "StartUp method should be overriden"
        return $false
    }

    [bool] DoRun() {
        throw "DoRun method should be overriden"
        return $false
    }

    [bool] Finalize(){
        throw "Finalize method should be overriden"
        return $false
    }
}