import json
import os
import subprocess
  
# Check if Azure CLI is installed, if not install it
if os.system('az --version') != 0:
    subprocess.check_call(["curl", "-sL", "https://aka.ms/InstallAzureCLIDeb", "|", "sudo", "bash"])

# Check if already logged in
try:
    result = subprocess.check_output(["az", "account", "show"])
    account_info = json.loads(result)
    print(f"Already logged in as {account_info['user']['name']}")
except subprocess.CalledProcessError:
    print("Not logged in. Logging in now...")
    subprocess.check_call(["az", "login", "--use-device-code"])

# use sed to replace the AgentResourceUsage diskQuotaInMB value in the mdsd.xml file to 90000
linux_command = 'sudo sed -i \'s|<AgentResourceUsage diskQuotaInMB="50000" />|<AgentResourceUsage diskQuotaInMB="90000" />|g\' /etc/opt/microsoft/azuremonitoragent/mdsd.xml\n'
# use powershell to replace the AgentResourceUsage diskQuotaInMB value in the mdsd.xml file to 90000
windows_command = "(Get-Content -Path C:\\ProgramData\\Microsoft\\AzureMonitor\\Agent\\mdsd.xml -Raw) -replace '<AgentResourceUsage diskQuotaInMB=\"50000\" />','<AgentResourceUsage diskQuotaInMB=\"90000\" />' | Set-Content -Path C:\\ProgramData\\Microsoft\\AzureMonitor\\Agent\\mdsd.xml"


with open('vms.json', 'r') as file:
    vms = json.load(file)

# loop through each item in data and print the values of the keys: resource-group and vmname
for vm in vms:
    vm_name = vm['vmname']
    resource_group = vm['resource-group']
    location = vm['location']

    # Define the command to get the VM details
    command = ["az", "vm", "show", "--name", vm_name, "--resource-group", resource_group, "--query", "storageProfile.osDisk.osType", "--output", "tsv"]

    # Run the command and get the output
    output = subprocess.check_output(command, universal_newlines=True)

    # Check if the VM is windows or linux and run the appropriate command shell script or powershell script:
    if output.strip() == 'Linux':
        run_command = ["az", "vm", "run-command", "invoke", "--command-id", "RunShellScript", "--name", vm_name, "--resource-group", resource_group, "--scripts", linux_command]
        subprocess.check_call(run_command)
    elif output.strip() == 'Windows':
        run_command = ["az", "vm", "run-command", "invoke", "--command-id", "RunPowerShellScript", "--name", vm_name, "--resource-group", resource_group, "--scripts", windows_command]
        subprocess.check_call(run_command)


with open('arc-machines.json', 'r') as file:
    connected_machines = json.load(file)

for machine in connected_machines:
    machine_name = machine['machine-name']
    resource_group = machine['resource-group']

    # Define the command to get the VM details
    command = ["az", "connectedmachine", "show", "--name", machine_name, "--resource-group", resource_group, "--query", "properties.osType", "--output", "tsv"]

    # Run the command and get the output
    output = subprocess.check_output(command, universal_newlines=True)

    # Check if the VM is windows or linux and run the appropriate command shell script or powershell script:
    if output.strip() == 'Linux':
        # run command using connectedmachine run-command create
        run_command = ["az", "connectedmachine", "run-command", "create", "--name", machine_name, "--resource-group", resource_group, "--script", linux_command]
        subprocess.check_call(run_command)
    elif output.strip() == 'Windows':
        # run command using connectedmachine run-command create
        run_command = ["az", "connectedmachine", "run-command", "create", "--name", machine_name, "--resource-group", resource_group, "--script", windows_command]
        subprocess.check_call(run_command)
