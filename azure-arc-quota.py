import time
#import pexpect
import json

#curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

#az login --use-device-code

# run this once to enable ssh

# Open the JSON file
with open('vms.json', 'r') as file:
    # Load the JSON data from the file
    vms = json.load(file)

# Now 'data' is a list of dictionaries that you can use in your code
print(vms)

# loop through each item in data and print the values of the keys: resource-group and vmname
for vm in vms:
    # az ssh vm --resource-group default-rg --name ubuntu-ssh 

    #child = pexpect.spawn(ssh_command)
    #az connectedmachine extension create --machine-name <arc enabled server name>
    # --resource-group <resourcegroup> --publisher Microsoft.Azure.ActiveDirectory 
    # --name AADSSHLogin --type AADSSHLoginForLinux --location <location>

    # Define the ssh command
    command = 'sudo sed -i \'s|<AgentResourceUsage diskQuotaInMB="50000" />|<AgentResourceUsage diskQuotaInMB="90000" />|g\' /etc/opt/microsoft/azuremonitoragent/mdsd.xml\n'
    print(command)

    ssh_command = 'az ssh vm --resource-group ' + vm['resource-group'] + ' --name ' + vm['vmname']

    # Start the ssh session
    child = pexpect.spawn(ssh_command)

    # Wait for the ssh session to start
    #child.expect(pexpect.EOF, timeout=None)

    #sleep 5 seconds
    time.sleep(3)

    # Send the command to the ssh session
    child.sendline(command)

    time.sleep(3)

    # Wait for the command to complete
    #child.expect(pexpect.EOF, timeout=None)

    # Close the ssh session
    child.close()
