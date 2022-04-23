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

4/  DLPIncidentSLABreach.py will update the incidents iteratively per Severity

Prerequisites
    DLPIncidentSLABreach.py is written in Python 3.8
    Symantec DLP 15.8 MP1
        A Symantec DLP user with API privileges 
    Python 3.8
    json requests logging datetime timedelta 

References:
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/15-8/DLP-Enforce-REST-APIs-overview/overview.html
