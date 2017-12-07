# Audit-S2D.ps1

This script only works on Hyperconverged S2D infrastructure. No information are given for disaggregated S2D environment.
This script is written to provide essential information about S2D hyperconverged infrastructure to check settings and consistency accross nodes
When the script has finished, an HTML file is generated and provide you a dashboard (see example in this repository).

To run the script, run the following commands:

$Credential = Get-Credential 

.\audit-S2D.ps1 -DomainName "MyDomain" -ClusterName "MyS2DHCICluster" -Credential $Credential -Path "C:\Where\My\HTML\is\Generated"

---- Tested environment -----
- Windows Server 1607
- Storage Spaces Direct in HyperConverged environment
- EN-US language OS

---- Not tested environment ----
- Windows Server 1709 or above
- Other OS language than EN-US

---- Not Working environment ----
- Windows Server 2012R2 or older release
- Disaggregated S2D environment

---- Next improvement ----
- Provide Cache / Capacity Ratio
- Provide information about reserved space
- Support disaggregated environment

If you have any issues or any requests, feel free to contact me.
