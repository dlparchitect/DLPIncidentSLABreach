"""

DLPIncidentSLABreach.py

PROVIDED AS-IS
The code is a) an example and b) provided as-is, we do not know your computing environment so you need to assess the script’s function and performance before implementing it.


1/ In Enforce, create a Status for incidents breaching the SLA. Use the variable dlpEnforceIncidentStatusSLABreach
dlpEnforceIncidentStatusSLABreach = 161
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/15-8/about-incident-remediation-vont_0025-d336e8/about-incident-status-attributes-v23016501-d336e8076.html

2/ Define the amount of hours in your SLA
dlpEnforceSeverityHighHours= 4
dlpEnforceSeverityMediumHours= 8
dlpEnforceSeverityLowHours= 12
dlpEnforceSeverityInfoHours= 16

3/ Define the amount of Incidents to return per API call. Max 10000
dlpEnforceIncidentPageSize = 2

4/  setDLPIncidentSLABreach.py will update the incidents iteratively per Severity

Prerequisites
    DLPIncidentSLABreach.py is written in Python 3.8
    Symantec DLP 15.8 MP1
        A Symantec DLP user with API privileges 
    Python 3.8
    json requests logging datetime timedelta 

References:
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/15-8/DLP-Enforce-REST-APIs-overview/overview.html

"""

import json
import requests
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict
from requests.packages import urllib3
import logging
from datetime import datetime, timedelta


#Symantec DLP parameters
dlpEnforceURLBase = 'https://EnforceIP/ProtectManager/webservices/v2/incidents/'
dlpEnforceUserName = 'RestAPIUser'
dlprEnforcePassword = 'Password'
# dlpEnforceIncidentStatusSLABreach is the status that we will assign to Incidents on SLA breach
dlpEnforceIncidentStatusSLABreach = 161
# In this example, we will query  incidents with Status = New 
dlpEnforceincidentStatusIdNew = 1
# Severity IDs
dlpEnforceSeverityHigh= 1
dlpEnforceSeverityMedium= 2
dlpEnforceSeverityLow= 3
dlpEnforceSeverityInfo= 4
# SLA HOURS PER INCIDENT SEVERITY
dlpEnforceSeverityHighHours= 4
dlpEnforceSeverityMediumHours= 8
dlpEnforceSeverityLowHours= 12
dlpEnforceSeverityInfoHours= 16
# dlpEnforcedictSLABreachSeverityHours is a dictionary with the number of Hours per Severity
dlpEnforcedictSLABreachSeverityHours = {dlpEnforceSeverityHigh:dlpEnforceSeverityHighHours, dlpEnforceSeverityMedium:dlpEnforceSeverityMediumHours, dlpEnforceSeverityLow:dlpEnforceSeverityLowHours, dlpEnforceSeverityInfo:dlpEnforceSeverityInfoHours}
# dlpEnforceIncidentPageSize controls the number of incidents to display
dlpEnforceIncidentPageSize = 2
# dlpEnforceIncidentNote
dlpEnforceIncidentNote = 'SLA Breach escalation. '

headers = CaseInsensitiveDict()
headers["Content-Type"] = "application/json"

#bolValidateSSL Validate HTTPS certificates
bolValidateSSL = False
#bolLoggingtoFile Log Results to a File
bolLoggingtoFile = True
loggingFile='incidentDLPMatches.log'

#Disable SSL warnings. DO NOT DO THIS IN PRODUCTION.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if bolLoggingtoFile:
    logging.basicConfig(filename='incidentDLPMatches.log', level=logging.DEBUG)


def getListofIncidentsOvertheSLA(Severity,Hours):
    datetime_SLA_Breach = datetime.now() - timedelta(hours = Hours)

    queryListofIncidents = '''
    {
    "select": [
        {
            "name": "incidentId"
        }
    ],
    "filter": {
        "filterType": "booleanLogic",
        "booleanOperator": "AND",
        "filters": [
            {
                "filterType": "booleanLogic",
                "booleanOperator": "AND",
                "filters": [
                    {
                        "filterType": "long",
                        "operandOne": {
                            "name": "incidentStatusId"
                        },
                        "operator": "IS_NOT_NULL"
                    },
                    {
                        "filterType": "localDateTime",
                        "operandOne": {
                            "name": "creationDate"
                        },
                        "operator": "LTE",
                        "operandTwoValues": [
                            "'''+datetime_SLA_Breach.strftime('%Y-%m-%dT%H:%M:%S')+'''"
                        ]
                    },
                    {
                        "filterType": "boolean",
                        "operandOne": {
                            "name": "isHidden"
                        },
                        "operator": "EQ",
                        "operandTwoValues": [
                            false
                        ]
                    },
                    {
                        "filterType": "long",
                        "operandOne": {
                            "name": "severityId"
                        },
                        "operator": "IN",
                        "operandTwoValues": ['''+str(Severity)+''']
                    },
                    {
                        "filterType": "long",
                        "operandOne": {
                            "name": "incidentStatusId"
                        },
                        "operator": "IN",
                        "operandTwoValues": ['''+str(dlpEnforceincidentStatusIdNew)+''']
                    }
                ]
            }
        ]
    },
    "orderBy": [
        {
            "field": {
                "name": "incidentId"
            },
            "order": "ASC"
        }
    ],
    "page": {
        "type": "offset",
        "pageNumber": 1,
        "pageSize": '''+str(dlpEnforceIncidentPageSize)+'''
    }
    }
    '''
    #Call DLP Rest API to get the list of Incidents. 
    #print(queryListofIncidents)
    return requests.post(dlpEnforceURLBase, headers=headers, data=queryListofIncidents, auth=HTTPBasicAuth(dlpEnforceUserName, dlprEnforcePassword), verify=bolValidateSSL)

    
def updateDLPIncidentswithNote(strListofIncidents,strIncidentNote):
    #Update Incidents with that indicates an SLA Breach
    queryupdateIncidents = '''
    {
       "incidentIds":[
       '''+strListofIncidents+'''
       ],
       "incidentStatusId":'''+str(dlpEnforceIncidentStatusSLABreach)+''',
       "incidentNotes":[
          {
             "note":"'''+strIncidentNote+'''"
          }
       ]
    }'''
    dlpresp = requests.patch(dlpEnforceURLBase, headers=headers, data=queryupdateIncidents, auth=HTTPBasicAuth(dlpEnforceUserName, dlprEnforcePassword), verify=bolValidateSSL)
    #print(dlpresp.status_code)
    #print(dlpresp.content)
    if bolLoggingtoFile:
        logging.debug('Incidents processed on ' + str(datetime.now()))
        logging.debug(queryupdateIncidents)
        

for eachSeverity in dlpEnforcedictSLABreachSeverityHours:
    dlpresponse = getListofIncidentsOvertheSLA(eachSeverity,dlpEnforcedictSLABreachSeverityHours[eachSeverity])
    dictofIncidents = json.loads(dlpresponse.content)
    #Validate that the dictionary is not empty
    if len(dictofIncidents) > 0:
        listofIncidentIds = ','.join(str(eachIncident['incidentId']) for eachIncident in dictofIncidents['incidents'])
        updateDLPIncidentswithNote(listofIncidentIds, dlpEnforceIncidentNote+str(dlpEnforcedictSLABreachSeverityHours[eachSeverity])+' Hours as a New Incident.' )    
    
"""
#Process High Severity Incidents 
dlpresponse = getListofIncidentsOvertheSLA(dlpEnforceSeverityHigh,dlpEnforceSeverityHighHours)
dictofIncidents = json.loads(dlpresponse.content)
listofIncidentIds = ','.join(str(eachIncident['incidentId']) for eachIncident in dictofIncidents['incidents'])
updateDLPIncidentswithNote(listofIncidentIds, dlpEnforceIncidentNote+str(dlpEnforceSeverityHighHours)+' Hours as a New High Severity Incident.' )

#Process Medium Severity Incidents 
dlpresponse = getListofIncidentsOvertheSLA(dlpEnforceSeverityMedium,dlpEnforceSeverityMediumHours)
dictofIncidents = json.loads(dlpresponse.content)
listofIncidentIds = ','.join(str(eachIncident['incidentId']) for eachIncident in dictofIncidents['incidents'])
updateDLPIncidentswithNote(listofIncidentIds, dlpEnforceIncidentNote+str(dlpEnforceSeverityMediumHours)+' Hours as a New Medium Severity Incident.' )


#Process Low Severity Incidents 
dlpresponse = getListofIncidentsOvertheSLA(dlpEnforceSeverityLow,dlpEnforceSeverityLowHours)
dictofIncidents = json.loads(dlpresponse.content)
listofIncidentIds = ','.join(str(eachIncident['incidentId']) for eachIncident in dictofIncidents['incidents'])
updateDLPIncidentswithNote(listofIncidentIds, dlpEnforceIncidentNote+str(dlpEnforceSeverityLowHours)+' Hours as a New Low Severity Incident.' )
"""
