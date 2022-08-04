Using Module ".\Neural_Engine.psm1"
# Import-Module C:\Users\abc\source\repos\Project_Automation\Engine.psm1

# Creating 2D array to create a layered network

class Network {
    [Neural_Engine[] []] hidden $Network

    Network(
        [int[]] $NetworkLayout,
        [float] $LearningRate
    ) {
        $this.Network = @()
        for($i = 0; $i -lt $NetworkLayout.Count; $i++) {
            $Layer = @()
            for ($n = 0; $n -lt $NetworkLayout[$i]; $n++) {
                if ($i -eq 0) {
                    $Layer += [Neural_Engine]::new($null, $NetworkLayout[$i], $LearningRate)
                } else {
                    $Layer += [Neural_Engine]::new($this.Network[$i-1], $NetworkLayout[$i-1], $LearningRate)
                }
            }
            $this.Network += , $Layer
        }
    }

    [float[]] Get_Output([float[]] $InputValues) {
        $Output = @()
        for($i = 0; $i -lt $this.Network.Count; $i++) {

            $Layer = $this.Network[$i]
            if($i -eq 0) {
                foreach($Neuron in $Layer) {
                    $Neuron.Get_Output($InputValues) | Out-Null
                }
            } else {
                foreach($Neuron in $Layer) {
                    $Neuron.Get_Output($InputValues) | Out-Null
                }
            }

            if($i -eq $this.Network.Count - 1) {
                for($j = 0; $j -lt $Layer.Count; $j++) {
                    $Output += $this.Network[$i][$j].Value
                }
            }
        }
        return $Output
    }

    [void] TrainNeuron ([float[]] $InputValues, [float[]] $TargetValues) {
        $this.Get_Output($InputValues) | Out-Null
        
        for ($i = $this.Network.Count - 1; $i -ge 0; $i--) {
            for ($j = 0; $j -lt $this.Network[$i].Count; $j++) {
                if ($i -eq $this.Network.Count - 1) {
                    $this.Network[$i][$j].BackPropagate($TargetValues[$j])
                } elseif ($i -eq 0) {
                    $this.Network[$i][$j].BackPropagate($InputValues)
                } else {
                    $this.Network[$i][$j].BackPropagate()
                }
            }
        }
    }

    TrainNetwork ([float [][]] $TrainingData, [int]$Epochs) {
        for ($i = 0; $i -lt $Epochs; $i++) {
            Write-Host "Epoch $i" -ForegroundColor Blue
            $TrainingSet = $TrainingData | Sort-Object {Get-Random}
            foreach ($row in $TrainingSet) {
                $InputData  = $row | Select-Object -First $this.Network[0].Count
                $OutputData = $row | Select-Object -Skip $this.Network[0].Count
                $this.TrainNeuron($InputData, $OutputData)
            }
        }
        
    }
}

# # create object to init Network such that input layer has 2 neurons, first hidden layer has 3 and output layer has 2 neurons
$Network = [Network]::new(@(2,3,2), 10) 
# # $Network.Get_Output(@(1,2))

# Write-Host "[*] Before training"        -ForegroundColor Red
# # Output shouldn't change before training
# $Network.Get_Output(@(1,2))

# Write-Host "[*] Training in progress"   -ForegroundColor Blue

# Start-Sleep 1

# # Training
# $Network.Train(@(1,2),@(1))

# Write-Host "[*] After training"         -ForegroundColor Green
# # Output after traning
# $Network.Get_Output(@(1,2))

$DataSet = @()
for ($i = 0; $i -le 100; $i++) {
    for ($j = 0; $j -le 100; $j++) {
        $DataSet += , @(($i / 10), ($j / 10), $($i -gt $j ? 1 : 0))
    }
}

$Network.TrainNetwork($DataSet, 30)

for ($i = 0; $i -le 10; $i++) {
    for ($j = 0; $j -le 10; $j++) {
        $Output = $Network.Get_Output(@($i, $j))
        $Color = "Red"
        if (($Output -gt .5 -and $i -gt $j) -or ($Output -lt .5 -and $i -le $j)) {
            $Color = "Green"
        }
        Write-Host "$i, $j -> $($Network.Get_Output(@($i, $j))) | $($i -gt $j ? 1: 0)" -ForegroundColor $Color
    }
}