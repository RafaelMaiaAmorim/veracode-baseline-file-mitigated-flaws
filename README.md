# veracode-baseline-file-mitigated-flaws
Python script example to create a Biselife file for pipelineScan with mitigated flaws

This is not an official Veracode project.

# Setup
Download Pipeline Scan Tool Version 23.6.0-0
Generate your VID and VKEy on Veracode plataform.

# Run
Create a baseline file to you project
https://docs.veracode.com/r/Run_a_Pipeline_Scan_from_the_Command_Line

By default, Pipeline Scan saves the scan results to a results.json file in the local directory. This file is also called an artifact.

Run Baseline.py with the parameters
python script.py -ID <ID> -key <Key> -app <ApplicationName> -baseline <BaselineFileName>

ID = Veracode ID
Key = Veracode Key
ApplicationName = Application Name on Veracode
BaselineFileName = Baseline file generated by Pipeline Scan




When the Script is executed it follows the following order

1 - Get the list of applications in Veracode using the application name as a filter

2 - Get the GUID of the application

3 - Gets all faults mitigated in the application

4 - Create a new baseline file with the name "Baseline_Mitigated_Result.json" placing only the flaws that were mitigated and approved in the Veracode platform for the selected application.



Run the pipeline scan informing the new baseline file generated with the parameter "-baseline Baseline_Mitigated_Result.json"

