from pandevice import firewall
from pandevice import policies
from pandevice import objects

import json
import logging
import os

logging.basicConfig(level=8)

SecHubSecurityRuleName = "SecHubSecurityRule"
SecHubNetwork = "SecHubNetwork"
SecHubThreat = "SecHubThreat"

event = {
"account": "140651570565", 
"region": "us-east-1", 
"detail": {
    "findings": [
        {
            "LastObservedAt": "2020-03-29T13:42:01Z", 
            "FirstObservedAt": "2020-03-29T13:41:57Z", 
            "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
            "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
            "Title": "API DescribeEventAggregates was invoked using root credentials.", 
            "Resources": [
            {
            "Region": "us-east-1", 
            "Partition": "aws", 
            "Type": "AwsIamAccessKey", 
            "Details": {
            "AwsIamAccessKey": {
            "UserName": "Root"
            }
            }, 
            "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
            }
            ], 
            "Workflow": {
            "Status": "NEW"
            }, 
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
            "ProductFields": {
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
            "count": "2", 
            "archived": "false", 
            "aws/securityhub/ProductName": "GuardDuty", 
            "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
            "action/awsApiCallAction/api": "DescribeEventAggregates", 
            "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
            "aws/securityhub/SeverityLabel": "LOW", 
            "resourceRole": "TARGET", 
            "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
            "action/awsApiCallAction/callerType": "Remote IP", 
            "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
            "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
            "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
            "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
            "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
            "aws/securityhub/CompanyName": "Amazon", 
            "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
            "action/actionType": "AWS_API_CALL", 
            "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
            }, 
            "WorkflowState": "NEW", 
            "CreatedAt": "2020-03-29T13:51:52.652Z", 
            "UpdatedAt": "2020-03-29T13:51:52.652Z", 
            "RecordState": "ACTIVE", 
            "SchemaVersion": "2018-10-08", 
            "AwsAccountId": "140651570565", 
            "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
            ], 
            "Severity": {
                "Product": 2, 
                "Normalized": 20, 
                "Label": "LOW"
            },
            "Network": {
                "Direction": "IN",
                "Protocol": "TCP",
                "SourceIpV4": "1.2.3.2",
                "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "SourcePort": "42",
                "SourceDomain": "here.com",
                "SourceMac": "00:0d:83:b1:c0:8e",
                "DestinationIpV4": "2.3.4.5",
                "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "DestinationPort": "80",
                "DestinationDomain": "there.com"
            }
        },
        {
            "LastObservedAt": "2020-03-29T13:42:01Z", 
            "FirstObservedAt": "2020-03-29T13:41:57Z", 
            "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
            "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
            "Title": "API DescribeEventAggregates was invoked using root credentials.", 
            "Resources": [
            {
            "Region": "us-east-1", 
            "Partition": "aws", 
            "Type": "AwsIamAccessKey", 
            "Details": {
            "AwsIamAccessKey": {
            "UserName": "Root"
            }
            }, 
            "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
            }
            ], 
            "Workflow": {
            "Status": "NEW"
            }, 
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
            "ProductFields": {
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
            "count": "2", 
            "archived": "false", 
            "aws/securityhub/ProductName": "GuardDuty", 
            "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
            "action/awsApiCallAction/api": "DescribeEventAggregates", 
            "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
            "aws/securityhub/SeverityLabel": "LOW", 
            "resourceRole": "TARGET", 
            "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
            "action/awsApiCallAction/callerType": "Remote IP", 
            "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
            "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
            "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
            "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
            "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
            "aws/securityhub/CompanyName": "Amazon", 
            "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
            "action/actionType": "AWS_API_CALL", 
            "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
            }, 
            "WorkflowState": "NEW", 
            "CreatedAt": "2020-03-29T13:51:52.652Z", 
            "UpdatedAt": "2020-03-29T13:51:52.652Z", 
            "RecordState": "ACTIVE", 
            "SchemaVersion": "2018-10-08", 
            "AwsAccountId": "140651570565", 
            "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
            ], 
            "Severity": {
                "Product": 2, 
                "Normalized": 20, 
                "Label": "LOW"
            },
            "Network": {
                "Direction": "IN",
                "Protocol": "TCP",
                "SourceIpV4": "1.2.3.3",
                "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "SourcePort": "42",
                "SourceDomain": "here.com",
                "SourceMac": "00:0d:83:b1:c0:8e",
                "DestinationIpV4": "2.3.4.5",
                "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "DestinationPort": "80",
                "DestinationDomain": "there.com"
            }
        },
            {
                "LastObservedAt": "2020-03-29T13:42:01Z", 
                "FirstObservedAt": "2020-03-29T13:41:57Z", 
                "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
                "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
                "Title": "API DescribeEventAggregates was invoked using root credentials.", 
                "Resources": [
                {
                "Region": "us-east-1", 
                "Partition": "aws", 
                "Type": "AwsIamAccessKey", 
                "Details": {
                "AwsIamAccessKey": {
                "UserName": "Root"
                }
                }, 
                "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
                }
                ], 
                "Workflow": {
                "Status": "NEW"
                }, 
                "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
                "ProductFields": {
                "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
                "count": "2", 
                "archived": "false", 
                "aws/securityhub/ProductName": "GuardDuty", 
                "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
                "action/awsApiCallAction/api": "DescribeEventAggregates", 
                "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
                "aws/securityhub/SeverityLabel": "LOW", 
                "resourceRole": "TARGET", 
                "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
                "action/awsApiCallAction/callerType": "Remote IP", 
                "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
                "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
                "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
                "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
                "aws/securityhub/CompanyName": "Amazon", 
                "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
                "action/actionType": "AWS_API_CALL", 
                "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
                }, 
                "WorkflowState": "NEW", 
                "CreatedAt": "2020-03-29T13:51:52.652Z", 
                "UpdatedAt": "2020-03-29T13:51:52.652Z", 
                "RecordState": "ACTIVE", 
                "SchemaVersion": "2018-10-08", 
                "AwsAccountId": "140651570565", 
                "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                "Types": [
                "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
                ], 
                "Severity": {
                    "Product": 2, 
                    "Normalized": 20, 
                    "Label": "LOW"
                    },
                    "Network": {
                        "Direction": "IN",
                        "Protocol": "TCP",
                        "SourceIpV4": "1.2.3.4",
                        "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                        "SourcePort": "42",
                        "SourceDomain": "here.com",
                        "SourceMac": "00:0d:83:b1:c0:8e",
                        "DestinationIpV4": "2.3.4.5",
                        "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                        "DestinationPort": "80",
                        "DestinationDomain": "there.com"
                    }
                },
                {
                    "LastObservedAt": "2020-03-29T13:42:01Z", 
                    "FirstObservedAt": "2020-03-29T13:41:57Z", 
                    "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
                    "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
                    "Title": "API DescribeEventAggregates was invoked using root credentials.", 
                    "Resources": [
                    {
                    "Region": "us-east-1", 
                    "Partition": "aws", 
                    "Type": "AwsIamAccessKey", 
                    "Details": {
                    "AwsIamAccessKey": {
                    "UserName": "Root"
                    }
                    }, 
                    "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
                    }
                    ], 
                    "Workflow": {
                    "Status": "NEW"
                    }, 
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
                    "ProductFields": {
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
                    "count": "2", 
                    "archived": "false", 
                    "aws/securityhub/ProductName": "GuardDuty", 
                    "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
                    "action/awsApiCallAction/api": "DescribeEventAggregates", 
                    "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
                    "aws/securityhub/SeverityLabel": "LOW", 
                    "resourceRole": "TARGET", 
                    "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
                    "action/awsApiCallAction/callerType": "Remote IP", 
                    "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
                    "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
                    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
                    "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
                    "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
                    "aws/securityhub/CompanyName": "Amazon", 
                    "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
                    "action/actionType": "AWS_API_CALL", 
                    "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
                    }, 
                    "WorkflowState": "NEW", 
                    "CreatedAt": "2020-03-29T13:51:52.652Z", 
                    "UpdatedAt": "2020-03-29T13:51:52.652Z", 
                    "RecordState": "ACTIVE", 
                    "SchemaVersion": "2018-10-08", 
                    "AwsAccountId": "140651570565", 
                    "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                    "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
                    ], 
                    "Severity": {
                        "Product": 2, 
                        "Normalized": 20, 
                        "Label": "LOW"
                        },
                        "Network": {
                            "Direction": "IN",
                            "Protocol": "TCP",
                            "SourceIpV4": "1.2.3.6",
                            "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                            "SourcePort": "42",
                            "SourceDomain": "here.com",
                            "SourceMac": "00:0d:83:b1:c0:8e",
                            "DestinationIpV4": "2.3.4.5",
                            "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                            "DestinationPort": "80",
                            "DestinationDomain": "there.com"
                        }
                    }
        ]
}, 
"detail-type": "Security Hub Findings - Imported", 
"source": "aws.securityhub", 
"version": "0", 
"time": "2020-03-29T13:55:15Z", 
"id": "13485b31-e4ac-8826-30a3-9a407b729b19", 
"resources": [
"arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93"
]
}
event2 = {
"account": "140651570565", 
"region": "us-east-1", 
"detail": {
    "findings": [
        {
            "LastObservedAt": "2020-03-29T13:42:01Z", 
            "FirstObservedAt": "2020-03-29T13:41:57Z", 
            "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
            "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
            "Title": "API DescribeEventAggregates was invoked using root credentials.", 
            "Resources": [
            {
            "Region": "us-east-1", 
            "Partition": "aws", 
            "Type": "AwsIamAccessKey", 
            "Details": {
            "AwsIamAccessKey": {
            "UserName": "Root"
            }
            }, 
            "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
            }
            ], 
            "Workflow": {
            "Status": "NEW"
            }, 
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
            "ProductFields": {
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
            "count": "2", 
            "archived": "false", 
            "aws/securityhub/ProductName": "GuardDuty", 
            "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
            "action/awsApiCallAction/api": "DescribeEventAggregates", 
            "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
            "aws/securityhub/SeverityLabel": "LOW", 
            "resourceRole": "TARGET", 
            "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
            "action/awsApiCallAction/callerType": "Remote IP", 
            "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
            "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
            "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
            "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
            "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
            "aws/securityhub/CompanyName": "Amazon", 
            "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
            "action/actionType": "AWS_API_CALL", 
            "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
            }, 
            "WorkflowState": "NEW", 
            "CreatedAt": "2020-03-29T13:51:52.652Z", 
            "UpdatedAt": "2020-03-29T13:51:52.652Z", 
            "RecordState": "ACTIVE", 
            "SchemaVersion": "2018-10-08", 
            "AwsAccountId": "140651570565", 
            "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
            ], 
            "Severity": {
                "Product": 2, 
                "Normalized": 20, 
                "Label": "LOW"
            },
            "Network": {
                "Direction": "IN",
                "Protocol": "TCP",
                "SourceIpV4": "2.2.3.2",
                "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "SourcePort": "42",
                "SourceDomain": "here.com",
                "SourceMac": "00:0d:83:b1:c0:8e",
                "DestinationIpV4": "2.3.4.5",
                "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "DestinationPort": "80",
                "DestinationDomain": "there.com"
            },
            "ThreatIntelIndicators": [
                            {
                                "Type": "IPV4_ADDRESS",
                                "Value": "8.8.8.10",
                                "Category": "BACKDOOR",
                                "LastObservedAt": "2018-09-27T23:37:31Z",
                                "Source": "Threat Intel Weekly",
                                "SourceUrl": "http://threatintelweekly.org/backdoors/8888"
                            }
                            ],
        },
        {
            "LastObservedAt": "2020-03-29T13:42:01Z", 
            "FirstObservedAt": "2020-03-29T13:41:57Z", 
            "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
            "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
            "Title": "API DescribeEventAggregates was invoked using root credentials.", 
            "Resources": [
            {
            "Region": "us-east-1", 
            "Partition": "aws", 
            "Type": "AwsIamAccessKey", 
            "Details": {
            "AwsIamAccessKey": {
            "UserName": "Root"
            }
            }, 
            "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
            }
            ], 
            "Workflow": {
            "Status": "NEW"
            }, 
            "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
            "ProductFields": {
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
            "count": "2", 
            "archived": "false", 
            "aws/securityhub/ProductName": "GuardDuty", 
            "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
            "action/awsApiCallAction/api": "DescribeEventAggregates", 
            "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
            "aws/securityhub/SeverityLabel": "LOW", 
            "resourceRole": "TARGET", 
            "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
            "action/awsApiCallAction/callerType": "Remote IP", 
            "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
            "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
            "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
            "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
            "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
            "aws/securityhub/CompanyName": "Amazon", 
            "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
            "action/actionType": "AWS_API_CALL", 
            "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
            }, 
            "WorkflowState": "NEW", 
            "CreatedAt": "2020-03-29T13:51:52.652Z", 
            "UpdatedAt": "2020-03-29T13:51:52.652Z", 
            "RecordState": "ACTIVE", 
            "SchemaVersion": "2018-10-08", 
            "AwsAccountId": "140651570565", 
            "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
            "Types": [
            "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
            ], 
            "Severity": {
                "Product": 2, 
                "Normalized": 20, 
                "Label": "LOW"
            },
            "Network": {
                "Direction": "IN",
                "Protocol": "TCP",
                "SourceIpV4": "2.2.3.3",
                "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "SourcePort": "42",
                "SourceDomain": "here.com",
                "SourceMac": "00:0d:83:b1:c0:8e",
                "DestinationIpV4": "2.3.4.5",
                "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                "DestinationPort": "80",
                "DestinationDomain": "there.com"
            },
            "ThreatIntelIndicators": [
                            {
                                "Type": "IPV4_ADDRESS",
                                "Value": "8.8.8.9",
                                "Category": "BACKDOOR",
                                "LastObservedAt": "2018-09-27T23:37:31Z",
                                "Source": "Threat Intel Weekly",
                                "SourceUrl": "http://threatintelweekly.org/backdoors/8888"
                            }
                            ],
        },
            {
                "LastObservedAt": "2020-03-29T13:42:01Z", 
                "FirstObservedAt": "2020-03-29T13:41:57Z", 
                "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
                "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
                "Title": "API DescribeEventAggregates was invoked using root credentials.", 
                "Resources": [
                {
                "Region": "us-east-1", 
                "Partition": "aws", 
                "Type": "AwsIamAccessKey", 
                "Details": {
                "AwsIamAccessKey": {
                "UserName": "Root"
                }
                }, 
                "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
                }
                ], 
                "Workflow": {
                "Status": "NEW"
                }, 
                "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
                "ProductFields": {
                "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
                "count": "2", 
                "archived": "false", 
                "aws/securityhub/ProductName": "GuardDuty", 
                "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
                "action/awsApiCallAction/api": "DescribeEventAggregates", 
                "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
                "aws/securityhub/SeverityLabel": "LOW", 
                "resourceRole": "TARGET", 
                "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
                "action/awsApiCallAction/callerType": "Remote IP", 
                "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
                "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
                "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
                "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
                "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
                "aws/securityhub/CompanyName": "Amazon", 
                "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
                "action/actionType": "AWS_API_CALL", 
                "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
                }, 
                "WorkflowState": "NEW", 
                "CreatedAt": "2020-03-29T13:51:52.652Z", 
                "UpdatedAt": "2020-03-29T13:51:52.652Z", 
                "RecordState": "ACTIVE", 
                "SchemaVersion": "2018-10-08", 
                "AwsAccountId": "140651570565", 
                "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                "Types": [
                "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
                ], 
                "Severity": {
                    "Product": 2, 
                    "Normalized": 20, 
                    "Label": "LOW"
                    },
                    "Network": {
                        "Direction": "IN",
                        "Protocol": "TCP",
                        "SourceIpV4": "1.2.3.4",
                        "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                        "SourcePort": "42",
                        "SourceDomain": "here.com",
                        "SourceMac": "00:0d:83:b1:c0:8e",
                        "DestinationIpV4": "2.3.4.5",
                        "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                        "DestinationPort": "80",
                        "DestinationDomain": "there.com"
                    }
                },
                {
                    "LastObservedAt": "2020-03-29T13:42:01Z", 
                    "FirstObservedAt": "2020-03-29T13:41:57Z", 
                    "GeneratorId": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47", 
                    "Description": "API DescribeEventAggregates was invoked using root credentials from IP address 199.167.52.5.", 
                    "Title": "API DescribeEventAggregates was invoked using root credentials.", 
                    "Resources": [
                    {
                    "Region": "us-east-1", 
                    "Partition": "aws", 
                    "Type": "AwsIamAccessKey", 
                    "Details": {
                    "AwsIamAccessKey": {
                    "UserName": "Root"
                    }
                    }, 
                    "Id": "AWS::IAM::AccessKey:ASIASBP34UWCXYDP5SM5"
                    }
                    ], 
                    "Workflow": {
                    "Status": "NEW"
                    }, 
                    "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty", 
                    "ProductFields": {
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lat": "37.4073", 
                    "count": "2", 
                    "archived": "false", 
                    "aws/securityhub/ProductName": "GuardDuty", 
                    "action/awsApiCallAction/remoteIpDetails/organization/org": "Palo Alto Networks", 
                    "action/awsApiCallAction/api": "DescribeEventAggregates", 
                    "action/awsApiCallAction/remoteIpDetails/ipAddressV4": "199.167.52.5", 
                    "aws/securityhub/SeverityLabel": "LOW", 
                    "resourceRole": "TARGET", 
                    "action/awsApiCallAction/remoteIpDetails/organization/asnOrg": "PAN0001", 
                    "action/awsApiCallAction/callerType": "Remote IP", 
                    "detectorId": "32b89345c25bffec12ac6cdd5dfe9d47", 
                    "action/awsApiCallAction/remoteIpDetails/country/countryName": "United States", 
                    "aws/securityhub/FindingId": "arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                    "action/awsApiCallAction/remoteIpDetails/geoLocation/lon": "-121.939", 
                    "action/awsApiCallAction/remoteIpDetails/organization/isp": "Palo Alto Networks", 
                    "action/awsApiCallAction/remoteIpDetails/city/cityName": "San Jose", 
                    "aws/securityhub/CompanyName": "Amazon", 
                    "action/awsApiCallAction/serviceName": "health.amazonaws.com", 
                    "action/actionType": "AWS_API_CALL", 
                    "action/awsApiCallAction/remoteIpDetails/organization/asn": "54538"
                    }, 
                    "WorkflowState": "NEW", 
                    "CreatedAt": "2020-03-29T13:51:52.652Z", 
                    "UpdatedAt": "2020-03-29T13:51:52.652Z", 
                    "RecordState": "ACTIVE", 
                    "SchemaVersion": "2018-10-08", 
                    "AwsAccountId": "140651570565", 
                    "Id": "arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93", 
                    "Types": [
                    "Software and Configuration Checks/AWS Security Best Practices/Policy:IAMUser-RootCredentialUsage"
                    ], 
                    "Severity": {
                        "Product": 2, 
                        "Normalized": 20, 
                        "Label": "LOW"
                        },
                        "Network": {
                            "Direction": "IN",
                            "Protocol": "TCP",
                            "SourceIpV4": "2.2.3.6",
                            "SourceIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                            "SourcePort": "42",
                            "SourceDomain": "here.com",
                            "SourceMac": "00:0d:83:b1:c0:8e",
                            "DestinationIpV4": "2.3.4.5",
                            "DestinationIpV6": "FE80:CD00:0000:0CDE:1257:0000:211E:729C",
                            "DestinationPort": "80",
                            "DestinationDomain": "there.com"
                        },
                        "ThreatIntelIndicators": [
                            {
                                "Type": "IPV4_ADDRESS",
                                "Value": "8.8.8.8",
                                "Category": "BACKDOOR",
                                "LastObservedAt": "2018-09-27T23:37:31Z",
                                "Source": "Threat Intel Weekly",
                                "SourceUrl": "http://threatintelweekly.org/backdoors/8888"
                            }
                            ],
                    }
        ]
}, 
"detail-type": "Security Hub Findings - Imported", 
"source": "aws.securityhub", 
"version": "0", 
"time": "2020-03-29T13:55:15Z", 
"id": "13485b31-e4ac-8826-30a3-9a407b729b19", 
"resources": [
"arn:aws:securityhub:us-east-1::product/aws/guardduty/arn:aws:guardduty:us-east-1:140651570565:detector/32b89345c25bffec12ac6cdd5dfe9d47/finding/eeb8934811a623d5d3760016c275ee93"
]
}
class PAN_FW:

    def __init__(self, fw_ip, u_name, paswd,
                 untrust_zone, trust_zone, security_rule_name,
                 rule_action, network_tag_name, dag_name, threat_tag_name, 
                 ):
        self.fw_ip = fw_ip
        self.u_name = u_name
        self.paswd = paswd 
        self.rulebase = None
        self.untrust_zone = untrust_zone
        self.trust_zone = trust_zone 
        self.security_rule_name = security_rule_name
        self.rule_action = rule_action
        self.dag_name = dag_name
        self.network_tag_name = network_tag_name
        self.threat_tag_name = threat_tag_name
        self.fw_hndl = None 

    def init_fw_handle(self):
        """
        Initialize a handle to the firewall
        """
        self.fw_hndl = firewall.Firewall(self.fw_ip, self.u_name, self.paswd)
        print self.fw_hndl.refresh_system_info()

    def cache_rulebase(self):
        """
        Method to cache a handle to the rulebase 
        """
        rulebase = policies.Rulebase()
        self.fw_hndl.add(rulebase)
        print policies.SecurityRule.refreshall(rulebase)
        self.rulebase = rulebase

    def check_security_rules(self):
        
        current_security_rules = policies.SecurityRule.refreshall(self.rulebase)

        print('Current security rules: {}'.format(len(current_security_rules)))
        for rule in current_security_rules:
            print('- {}'.format(rule.name))
        print "Checking is rule {} exists ".format(self.security_rule_name)

        for sr in current_security_rules:
            if self.security_rule_name == sr.name:
                return True
        
        return False

    def check_dag_exists(self, dag_name):
        """
        Introspect the VM-Series FW and check if the 
        DAG exists
        :param device: 
        :param group_name: 
        :return: 
        """
        dag_list, _ = self.get_all_address_group()
        print "DAG list = {}".format(dag_list)
        if dag_name in dag_list:
            return True 
        else:
            return False

    def get_all_address_group(self):
        """
        Retrieve all the tag to IP address mappings
        :param device:
        :return:
        """
        exc = None
        try:
            ret = objects.AddressGroup.refreshall(self.fw_hndl)
        except Exception, e:
            print e
            exc = e

        if exc:
            return (False, exc)
        else:
            l = []
            for item in ret:
                l.append(item.name)
            return l, exc

    def add_address_group(self, ag_object):
        """
        Create a new dynamic address group object on the
        PAN FW.
        """

        self.fw_hndl.add(ag_object)
        ag_object.create()
        return True

    @staticmethod
    def create_address_group_object(**kwargs):
        """
        Create an Address object
        @return False or ```objects.AddressObject```
        """
        ad_object = objects.AddressGroup(
            name=kwargs['address_gp_name'],
            dynamic_value=kwargs['dynamic_value'],
            description=kwargs['description'],
            tag=kwargs['tag_name']
        )
        if ad_object.static_value or ad_object.dynamic_value:
            return ad_object
        else:
            return None

    def register_ip_to_tag_map(self, ip_addresses, tag_name):
        """
        :param device:
        :param ip_addresses:
        :param tag:
        :return:
        """

        exc = None
        try:
            self.fw_hndl.userid.register(ip_addresses, [tag_name])
        except Exception, e:
                exc = get_exception()

        if exc:
            return (False, exc)
        else:
            return (True, exc)

    @staticmethod
    def create_security_rule(**kwargs):
        """
         Create a security rule object and return 
         the object handle
        """
        security_rule = policies.SecurityRule(
            name=kwargs['rule_name'],
            description=kwargs['description'],
            fromzone=kwargs['source_zone'],
            source=kwargs['source_ip'],
            source_user=kwargs['source_user'],
            hip_profiles=kwargs['hip_profiles'],
            tozone=kwargs['destination_zone'],
            destination=kwargs['destination_ip'],
            application=kwargs['application'],
            service=kwargs['service'],
            category=kwargs['category'],
            log_start=kwargs['log_start'],
            log_end=kwargs['log_end'],
            action=kwargs['action'],
            type=kwargs['rule_type']
        )

        if 'tag_name' in kwargs:
            security_rule.tag = kwargs['tag_name']

        # profile settings
        if 'group_profile' in kwargs:
            security_rule.group = kwargs['group_profile']
        else:
            if 'antivirus' in kwargs:
                security_rule.virus = kwargs['antivirus']
            if 'vulnerability' in kwargs:
                security_rule.vulnerability = kwargs['vulnerability']
            if 'spyware' in kwargs:
                security_rule.spyware = kwargs['spyware']
            if 'url_filtering' in kwargs:
                security_rule.url_filtering = kwargs['url_filtering']
            if 'file_blocking' in kwargs:
                security_rule.file_blocking = kwargs['file_blocking']
            if 'data_filtering' in kwargs:
                security_rule.data_filtering = kwargs['data_filtering']
            if 'wildfire_analysis' in kwargs:
                security_rule.wildfire_analysis = kwargs['wildfire_analysis']
        return security_rule

    def insert_rule(self, sec_rule):
        """
        Insert the policy for AWS Security Hub
        at the top of the ruleset. 
        """
        print("Inserting Rule into the top spot.")
        self.rulebase.insert(0, sec_rule)
        sec_rule.apply_similar()
        #rulebase.apply()

    def commit(self):
        """
         Commit settings on the firewall. 
        """ 
        try:
            self.fw_hndl.commit(sync=True)
        except Exception, e:
            print("exception occurred.. {}".format(e))
            return e

class EnvSettings:

    def __init__(self, fw_ip, username, password,
                 untrust_zone_name, trust_zone_name, 
                 security_rule_name, rule_action,
                 network_tag_name, 
                 sechub_dag_name, threat_tag_name):
        self.fw_ip = fw_ip
        self.username = username
        self.password = password
        self.untrust_zone_name = untrust_zone_name
        self.trust_zone_name = trust_zone_name 
        self.security_rule_name = security_rule_name
        self.rule_action = rule_action
        self.network_tag_name = network_tag_name
        self.sechub_dag_name = sechub_dag_name
        self.threat_tag_name = threat_tag_name

    def __str__(self):
        return "FW IP: {}\n"\
                "Untrust Zone: {}\n"\
                "Trust Zone: {}\n"\
                "Security Rule Name: {}\n"\
                "DAG Name: {}\n"\
                "Tag Name for DAGS: {},{}".format(self.fw_ip,
                self.untrust_zone_name, self.trust_zone_name, 
                self.security_rule_name, self.sechub_dag_name,
                self.network_tag_name, 
                self.threat_tag_name)

def handle_security_hub_finding(fw, event, context=None):
    """
    Function to scrub the security hub finding. 
    The function also validates the fields required to be
    handled by the VM-Series FW
    """
    processed = False

    print "Processing the security hub findings"
    try: 
        print "get details"
        detail = event.get("detail", None)
        print "detail : {}".format(detail)
        if detail:
            findings = detail.get("findings", None)
            print "findings: {}".format(findings)
            if findings:
                nwfs, thtfs = process_security_hub_finding(findings)
                
                if nwfs:
                    # Add ip to tag mapping to SecHubNetwork tags
                    print "Adding IP {} to tag SecHubNetwork".format(nwfs)
                    fw.register_ip_to_tag_map(nwfs, "SecHubNetwork")
                    if not processed:
                        processed = True
                    pass
                if thtfs:
                    # Add ip to tag mapping to SecHubThreat tags
                    fw.register_ip_to_tag_map(thtfs, "SecHubThreat")
                    if not processed:
                        processed = True
                    pass 
        else:
            print "Unable to process the detail key in the findings."
        
        if processed:
            print "Security Hub findings were retrieved and applied to the firewall."
    except Exception, e:
        print "Exception occurred while processing security hub finding: {}".format(e)

def process_security_hub_finding(findings):

    network_findings = []
    threat_findings = []


    for finding in findings:

        severity = None # "CRITICAL" | "HIGH"
        network_ip = None 
        threat_ip = None 

        severity_data = finding.get("Severity", None)
        if severity_data:
            severity = severity_data.get("Label")

        # Probably need to handle CRITICAL and HIGH severity 
        # only. Or this can be configurable 

        # Handle any "Network" keys
        network_data = finding.get("Network", None)
        if network_data:
            if network_data.get("Direction") == "IN":
                network_ip = network_data.get("SourceIpV4")
                print "Found Network->SourceIpV4 in data: {}".format(network_ip)
                network_findings.append(network_ip)

        # Handle any "ThreatIntelIndicators"
        threat_data = finding.get("ThreatIntelIndicators", None)
        print "Threat data: {}".format(threat_data)
        for threat in threat_data or []:
            if threat:
                if threat.get("Type", None) and threat.get("Type") == "IPV4_ADDRESS":
                    threat_ip = threat.get("Value")
                    print "Found ThreatIntelIndicators->Value in data: {}".format(threat_ip)
                    threat_findings.append(threat_ip)

    if len(network_findings) or len(threat_findings):
        return (network_findings, threat_findings) 
    else:
        return (None, None)


def check_security_rule_exists(device, rule_name):
    output = device.op("show system info")

    print("System info: {}".format(output))

    rulebase = policies.Rulebase()
    device.add(rulebase)
    current_security_rules = policies.SecurityRule.refreshall(rulebase)

    print('Current number of security rules: {}'.format(len(current_security_rules)))
    for rule in current_security_rules:
        print('- {}'.format(rule.name))
        if rule.name == rule_name:
            return True
    return False

def check_dags_exist(fw_hndl):
    """
    Method to check if DAGs exist on FW.
    :param fw
    """

    if not fw_hndl.check_dag_exists(SecHubNetwork):
        print "Creating DAG SecHubNetwork"
        ag_object = PAN_FW.create_address_group_object(address_gp_name=fw_hndl.dag_name,
                                            dynamic_value=fw_hndl.network_tag_name,
                                            description='DAG for SecurityHub Network Mappings',
                                            tag_name=None
                                            )
        fw_hndl.add_address_group(ag_object)
        print "Created a new DAG on the FW called SecHubNetwork"
        found = True
    else:
        print "DAG SecHubNetwork already exists on the FW. "

    if not fw_hndl.check_dag_exists(SecHubThreat):
        ag_object = PAN_FW.create_address_group_object(address_gp_name=SecHubThreat,
                                            dynamic_value=fw_hndl.threat_tag_name,
                                            description='DAG for SecurityHub Threat Mappings',
                                            tag_name=None
                                            )
        fw_hndl.add_address_group(ag_object)
        print "Created a new DAG on the FW called SecHubThreat"
    else:
        print "DAG SecHubNetwork already exists on the FW. "


def get_vm_series_handle(env_settings):
    """
      Establish a connection and a handle to the 
      VM-Series FW. 
    """
    fw_hndl = PAN_FW(env_settings.fw_ip, env_settings.username, 
                     env_settings.password, env_settings.untrust_zone_name, 
                     env_settings.trust_zone_name, env_settings.security_rule_name, 
                     env_settings.rule_action, env_settings.network_tag_name, 
                     env_settings.sechub_dag_name, env_settings.threat_tag_name)

    fw_hndl.init_fw_handle()
    fw_hndl.cache_rulebase()

    return fw_hndl


def lambda_handler(event, context):

    # Recipe to handle AWS Security Hub findings
    # 1. Check to ensure two DAGs have been created, namely
    #     SecHubNetwork and SecHubThreat
    # 2. If DAGs don't exist, then create the DAG
    # 3. Check to see if a security rule referencing the DAG already exists
    # 3. Once check has been made, then add the IP to Tag mappings

    env_obj = EnvSettings(os.environ['FWIP'],
                        os.environ['USERNAME'],
                        os.environ['PASSWORD'],
                        os.environ['UNTRUST_ZONE'],
                        os.environ['TRUST_ZONE'],
                        os.environ.get('SECURITY_RULE_NAME', 'security_hub_rule'),
                        os.environ.get('RULE_ACTION', 'deny'),
                        os.environ.get("NETWORK_TAG_NAME", "SecHubNetwork"),
                        os.environ.get("SECURITYHUB_DAG_NAME", "security_hub_dag"),
                        os.environ.get("THREAT_TAG_NAME", "SecHubThreat")
    )

    fw_hndl = get_vm_series_handle(env_obj)
    print "Checking if the DAGs exist on the firewall"
    check_dags_exist(fw_hndl)
    print "Checking if the security rules already exist on the firewall"
    if not fw_hndl.check_security_rules():
        sec_pol = PAN_FW.create_security_rule(
            rule_name=fw_hndl.security_rule_name,
                description='description',
                tag_name=[],
                source_zone=fw_hndl.untrust_zone,
                destination_zone=fw_hndl.trust_zone,
                source_ip=[fw_hndl.dag_name, SecHubThreat],
                source_user=['any'],
                destination_ip=['any'],
                category=['any'],
                application=['any'],
                service=['application-default'],
                hip_profiles=['any'],
                group_profile={},
                antivirus={},
                vulnerability={},
                spyware={},
                url_filtering={},
                file_blocking={},
                data_filtering={},
                wildfire_analysis={},
                log_start=False,
                log_end=True,
                rule_type='universal',
                action=fw_hndl.rule_action
            )
        print "security policy", sec_pol
        fw_hndl.insert_rule(sec_pol)
        print "****** Done adding security rule ********"        
    else:
        print "Security rule {} already exists.".format('aws_security_hub_rules')

    print("[Lambda handler] Received event: " + json.dumps(event, indent=2))

    handle_security_hub_finding(fw_hndl, event, context)
    fw_hndl.commit()
    print("All operations done...")

if __name__ == "__main__":
    lambda_handler(event2, None)
