class Neural_Engine {
    [Int32]             hidden $NumberOfInputs
    [float[]]           hidden $Weights
    [Neural_Engine[]]   hidden $InputNeurons
    [bool]              hidden $IsInputNeuron
    [float[]]           hidden $NetworkErrors
    [float]             hidden $LearningRate

    [float]                     $Value

    Neural_Engine (
        [Neural_Engine[]]     $InputNeurons,
        [Int32]               $NumberOfInputs,
        [float]               $LearningRate
    ) {
        $this.InputNeurons      = $InputNeurons
        $this.NumberOfInputs    = $NumberOfInputs
        $this.IsInputNeuron     = $true
        $this.Value             = 0
        $this.NetworkErrors     = @()
        $this.LearningRate      = $LearningRate

        if($this.InputNeurons.count -eq 0) {
            $this.IsInputNeuron = $true
        }

        $this.Weights = [float[]]::new($NumberOfInputs + 1) # +1 for bias
        for($i = 0; $i -lt $NumberOfInputs + 1; $i++) {
            $this.Weights[$i] = (Get-Random -Minimum -10 -Maximum 10) / 10 # Weight is random between -1 and 1   
        }
        
    }

    [float] Get_Output([float[]] $InputValues) {
        $exp = [float]0

        # Multiply inputs by weights
        for($i = 0; $i -lt $this.NumberOfInputs; $i++) {
            $exp += $this.Weights[$i] * $InputValues[$i]
        }
        # Add the bias
        $exp += $this.Weights[$this.NumberOfInputs]
        $Output = [float] (1.0 / (1.0 + [System.Math]::Exp(-1 * $exp)))
        $this.Value = $Output
        return $Output
    }

    [float] Get_Output() {
        $exp = [float]0

        # Multiply inputs by weights
        for($i = 0; $i -lt $this.NumberOfInputs; $i++) {
            $exp += $this.Weights[$i] * $this.InputNeurons[$i].Value
        }
        # Add the bias
        $exp += $this.Weights[$this.NumberOfInputs]
        # Sigmoid function
        $Output = [float] (1.0 / (1.0 + [System.Math]::Exp(-1 * $exp)))
        $this.Value = $Output
        return $Output
    }

    # *********************************BackPropagation Section*********************************

    AddError([float] $err) {
        $this.NetworkErrors += $err
    }

    [float] Get_Derivative() {
        return ($this.Value * (1.0 - $this.Value))
    }

    # ***********Output Layer*************

    [float] Get_Error([float] $ExpectedTargetValues) {
        return ($this.Value - $ExpectedTargetValues) * $this.Get_Derivative()
    }

    BackPropagate([float] $ExpectedTargetValues) {
        $err = $this.Get_Error($ExpectedTargetValues)

        for ($i = 0; $i -lt $this.InputNeurons.Count; $i++) {
            $this.InputNeurons[$i].AddError($err * $this.Weights[$i])
            $this.Weights[$i] -= $this.InputNeurons[$i].Value * $err * $this.LearningRate
        }
        $this.Weights[$this.InputNeurons.Count] += -1 * $err * $this.LearningRate
    }

    # ***********END OF -> Output Layer*************

    # ***********Hidden Layer*************

    [float] Get_Error() {

        # For non ourput neurons
        $err = 0
        foreach ($ne in $this.NetworkErrors) {
            $err += $ne
        }
        $this.NetworkErrors = @()
        return $err * $this.Get_Derivative()
    }

    BackPropagate() {
        $err = $this.Get_Error()

        for ($i = 0; $i -lt $this.InputNeurons.Count; $i++) {
            $this.InputNeurons[$i].AddError($err * $this.Weights[$i])
            $this.Weights[$i] -= $this.InputNeurons[$i].Value * $err * $this.LearningRate
        }
        $this.Weights[$this.InputNeurons.Count] += -1 * $err * $this.LearningRate
    }

    # ***********END OF -> Hidden Layer*************

    # ***********Input Layer*************

    BackPropagate([float[]] $NetworkInputs) {
        $err = $this.Get_Error()

        for ($i = 0; $i -lt $NetworkInputs.Count; $i++) {
            $this.Weights[$i] += -1 * $NetworkInputs[$i] * $err * $this.LearningRate
        }
        $this.Weights[$NetworkInputs.Count] += -1 * $err * $this.LearningRate
    }
    # ***********END OF -> Input Layer*************

    # *********************************END OF -> BackPropagation Section*********************************
}