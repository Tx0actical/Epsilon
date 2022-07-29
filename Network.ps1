Using Module ".\Neural_Engine.psm1"
# Import-Module C:\Users\abc\source\repos\Project_Automation\Engine.psm1

$Neuron1 = [Neural_Engine]::new(@(),1)
$Neuron1
# $Neuron1.Get_Output(@(10,20))

# $Neuron2 = [Neural_Engine]::new(@($Neuron1),1)
# $Neuron2.GetOutput()