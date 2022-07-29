class Neural_Engine {
    [Int32]             hidden $NumberOfInputs
    [float[]]           hidden $Weights
    [Neural_Engine[]]   hidden $InputNeurons
    [bool]              hidden $IsInput

    [float]                     $Value

    Neural_Engine (
        [Neural_Engine[]]   $InputNeurons,
        [int]               $NumberOfInputs
    ) {
        $this.InputNeurons      = $InputNeurons
        $this.$NumberOfInputs   = $NumberOfInputs
        $this.IsInput           = $true
        $this.Value             = 0

        if($this.InputNeurons.count -eq 0) {
            $this.IsInput = $true
        }

        $this.Weights = [float[]]::new($NumberOfInputs + 1) # +1 for bias
        for($i = 0; $i -lt $NumberOfInputs + 1; $i++) {
            $this.Weights[$i] = (Get-Random -Minimum 10 -Maximum 10) / 10 # Weight is random between -1 and 1   
        }
        $this.Value = 0
    }

    [float] Get_Output([float[]] $InputValues) {
        $Exp = [float]0

        # Multiply inputs by weights
        for($i = 0; $i -lt $this.NumberOfInputs; $i++) {
            $Exp += $this.Weights[$i] * $InputValues[$i]
        }
        # Add the bias
        $Exp += $this.Weights[$this.NumberOfInputs]
        $Output = [float] (1.0 / (1.0 + [System.Math]::Exp(-1 * $Exp)))
        $this.Value = $Output
        return $Output
    }

    [float] Get_Output() {
        $Exp = [float]0

        # Multiply inputs by weights
        for($i = 0; $i -lt $this.NumberOfInputs; $i++) {
            $Exp += $this.Weights[$i] * $this.InputNeurons[$i].Value
        }
        # Add the bias
        $Exp += $this.Weights[$this.NumberOfInputs]
        # Sigmoid function
        $Output = [float] (1.0 / (1.0 + [System.Math]::Exp(-1 * $Exp)))
        $this.Value = $Output
        return $Output
    }
}