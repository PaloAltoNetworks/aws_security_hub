# aws_security_hub
This implementation integrates the AWS Security Hub insights and makes it actionable on the VM-Series FW.

# Theory of Operation

The ```aws_security_hub``` python script upon invocation does the following:

- interacts with AWS Security Hub and sources indicators of compromise. 
- IOC's when available, trigger the invocation of a lambda function
- the lambda funciton processes the IOC and extracts details such as IP and add the
  IP to the appropriate DAG Tag.
- interacts with the firewall to:
    -  create a dynamic address group
    -  create security rule and associates the dynamic address group with the security rule 
    -  as new IOC's are detected the IP's are registered with the tag which is used in the DAG

NOTE:: For the purpose of this integration we focus on the Network and ThreatIntelIndicators findings.
       Two DAG's are created on the FW: (1) SecHubNetwork and (2) SecHubThreat

# Setup

## High Level Steps

- Create and configure the lambda function
- Enable Security Hub on AWS in all the required regions. 
- Optionally enable Guard Duty in all the required regions as well. 
- Setup a Cloud Watch event rule to trigger the lambda function when findings are available on 
  Security hub. Please review AWS documentation on the procedure to perform this.  


## Create and configure the lambda function 

- Create a new lambda function 
- Navigate down to the "Function Code" section 
- Choose the option to upload a zip file for the lambda function 
- Upload the sechub.zip file
- Change the name of the entry point for the lambda function in the Handler text box. 
- Ensure the Handler text box has the value: ```pan_aws_security_hub.lambda_handler``` 
 
## Setup the Environment variables 

    "Add" the following environment variables to the lambda functions configuraion. 
    There will be a total of 10 environment variables. 

    Values show below are representative. Please change these to match your specific configuration. Please see 
    the description for these variables provided in the section below.

    FWIP=192.168.55.10
    USERNAME='username'
    PASSWORD='password'
    UNTRUST_ZONE='L3-untrust'
    TRUST_ZONE='L3-trust'
    SECURITY_RULE_NAME='securityhub'
    RULE_ACTION='deny'
    SECURITYHUB_DAG_NAME='securitydag'

    # These environment variables are recommended to be used with the values shown.
    THREAT_TAG_NAME='SecHubThreat'
    NETWORK_TAG_NAME='SecHubNetwork'


## Description of the environment variables 

    + FWIP: IP Address to communicate with the firewall
    + USERNAME: Username to authenticate with the firewall
    + PASSWORD: Password used for authentication
    + UNTRUST_ZONE: The name of the untrust zone as configured on the firewall
    + TRUST_ZONE: The name of the trust zone as configured on the firewall
    + SECURITY_RULE_NAME: A name for the security rule which will be created to enforce the findings from AWS Security Hub. 
    + RULE_ACTION: A valid value for the action to be taken on a security rule match. The suggested value is 'deny'
    + SECURITYHUB_DAG_NAME: A name for the Dynamic Address Group to create on the firewall, which will be associated with the security rule. 
    + THREAT_TAG_NAME: Name for the Threat tag info from findings 
    + NETWORK_TAG_NAME: Name for the Network tag info from findings

## Next step
- the last step in the process is when new findings are available, the lambda function 
  will automatically get triggered and will execute the logic to map IOC's to Dynamic Address Groups on the 
  VM-Series Firewall. 

- Debugging can be performed by introspecting the logs from the Lambda function. 