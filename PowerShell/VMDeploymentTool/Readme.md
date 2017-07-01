This set of tool enables to deploy hyper-v virtual machines from a template file. You can find below the current feature provided. I have added a word file for the documentation.

This tool is in beta and so some bugs could appears

(support only for Hyper-V host in WS2016 in a cluster)

- Deploy a complete Gen 2 Hyper-V Virtual Machine.
- Set the main settings of the VM (vCPU, Memory, Note, integration services)
- Deploy the VM from a syspreped VHDX
- Add the VM to the domain automatically
- Set static IP addresses automatically
- Change the VM name automatically
- Rename network adapters automatically
- Add as many network adapters needed with VLAN configuration, name and Device Naming (more is coming)
- Add as many virtual disk as needed (dynamic or fixed)
- Add the VM in the cluster and start it automatically

More features will be added in the time. I'd like to add the following feature in next release:
- Set the virtualization exposition (nested Hyper-V)
- Add settings regarding network adapters
- Make this script works on standalone Hyper-V
