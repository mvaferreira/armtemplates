# ARM Templates for Remote Desktop Services

This ARM Template sample code will deploy a lab for Remote Desktop Services for Session Deployment. The goal is to deploy a fully redundant, highly available solution for Remote Desktop Services, using Windows Server 2019.

It requests valid public certificates for the deployment automatically from Let's Encrypt.

Even though multiple services are deployed, it is not using Azure best practices, since this is a LAB environment. Also, it does not integrate into existing resources, except for the Azure Public DNS Zone. Does not integrate with existing Active Directory domain and no networking connectivity with onpremises.

**WVD is the production ready environment for Remote Desktop Services** -> [Windows Virtual Desktop](https://azure.microsoft.com/en-us/services/virtual-desktop/)

## Configuration

All of VMs are configured as Azure Spot VMs (deallocate) and Azure Hybrid Benefit. Make sure you have licenses onpremises for Windows Server 2019 Datacenter, otherwise, change VM configuration.

By default, this will deploy 2 VMs of this type:

- Active Directory/Domain Controller
- Remote Desktop Services Web Access/Gateway role
- Remote Desktop Services Connection Broker role
- Remote Desktop Services Licensing role
- Remote Desktop Services Session Host role

Additionally, it will deploy:

- Azure SQL Server
- Azure SQL Database, used by RDS Connection Brokers for High Availability configuration
- Azure Public Load Balancer for Web Access/Gateway
- Azure Internal Load Balancer for Web Access/Gateway and Connection Brokers
- Azure Storage Account for VM diagnostics
- Single Azure Network Security Group, with required rules for HTTP/HTTPs/Gateway via UDP/3391 for RDS
- Single Azure Resource Group containing all resources
- Single Azure Virtual Network
- Single Azure Virtual Subnet
- Network Interfaces and Public IP addresses
- New Active Directory single forest, single domain

Final expected configuration is:

- Fully redundant, highly available Remote Desktop Services 2019 for Session Desktops
- Azure DNS zones with CNAMEs to public load balancer dns label
- Two [Let's encrypt](https://letsencrypt.org/) certificates for RDWebAccess/RDGateway and RDRedirector/RDPublishing

## Notes

To be able to request certificates and have the highly available environment, the deployment expects the following:

- Azure Resource Group already pre-created with a validated Azure Public DNS zone you have authority. The Resource Group and Public DNS Zone are defined in parameters "DNSZoneResourceGroup" and "DNSZone".
- This Resource Group containing the Azure Public DNS Zone must be in the same Azure Subscription you are deploying the ARM Template.
- Using this ARM Template on Visual Studio Code with ARM extension, incorrectly triggers ARM Template validation errors, due to using Nested Templates with "inner" scope option, as described on [issue 730](https://github.com/microsoft/vscode-azurearmtools/issues/730). This can be safely ignored as the template is valid.
- Uses some code from examples [301-create-ad-forest-with-subdomain](https://github.com/Azure/azure-quickstart-templates/tree/master/301-create-ad-forest-with-subdomain) and [rds-deployment-existing-ad](https://github.com/Azure/azure-quickstart-templates/tree/master/rds-deployment-existing-ad) on Azure QuickStart Templates.