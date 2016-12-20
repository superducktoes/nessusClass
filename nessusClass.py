import json
import requests

#replace these with the keys for the account used for scanning
accessKey = ""
secretKey = ""

url = "https://cloud.tenable.com/"
headers = {'X-ApiKeys': 'accessKey=' + str(accessKey) + '; secretKey = ' + str(secretKey) + ';'}

class Scan:

        """Scan - Used for building and launching scans. Does not take any attributes when creating the class.
          - Requires scan name and host to build class

        Attributes:

        displayHosts - returns the list of hosts to be scanned
        addHosts - add to the hosts being scanned
        showPolicies - returns a list of available scan policies in json
        setPolicy - takes the ID of the scan policy to use
        selectedPolicy - returns the policy ID set for the scan
        launchScan - runs the scan with the set scanner and policy.
          - returns: scanID
        
        """
        
        def __init__(self,name,hosts):
                self.name = name
                self.hosts = hosts

        def displayHosts(self):
                return self.hosts

        # adds a host to the list of hosts to be scanned. takes either an IP/DNS or CIDR
        def addHosts(self,hosts):
                str(hosts)
                self.hosts += ("," + hosts)

        # returns a list of all available scan policies for the user
        def showPolicies(self):
                policies = requests.get(url+"policies/",headers=headers,verify=True)
                listPolicies = policies.json()["policies"]
                return listPolicies
        
        def setPolicy(self,policyID):
                self.policy = policyID

        def selectedPolicy(self):
                return self.policy

        def showScanners(self):
                scanners = requests.get(url+"scanners/",headers=headers,verify=True)
                listScanners = scanners.json()["scanners"]
                return listScanners

        def setScanner(self,scannerID):
                self.scannerID = scannerID

        def displayScanner(self):
                return self.scannerID

        # used to change the name of the scan set by the constructor
        def updateScanName(self,name):
                self.scanName = name

        def displayScanname(self):
                return self.scanName

        def launchScan(self):
                
                # gets the uuid of the template to use before the scan is launched below.
                # if there is an issue with the template it returns the error
                
                try:
                        templateInfo = requests.get(url+"policies/"+str(self.policy),headers=headers,verify=True)
                        templateInfo = templateInfo.json()["uuid"]
                        templateUuid = str(templateInfo)
                        
                except Exception as e:
                      print("Error: " + str(e))
                      print("\nMake sure that the scan policy is set before launching the scan.")
                      scanData = e

                # launches the scan
                scan = {"uuid":templateUuid,
                        "settings": {
                                "name": self.name,
                                "enabled": "true",
                                "scanner_id":self.scannerID,
                                "policy_id":self.policy,
                                "text_targets":self.hosts,
                                "launch_now":"true"}
                }

                # once the scan is launched this filters out the id of the scan which is returned to use to check the status
                # and download the results.
                
                scanData = requests.post(url+"scans",json=scan,headers=headers,verify=True)
                scanData = scanData.json()['scan']
                scanData = scanData['id']
                
                return scanData

class Report:

        #scanID is returned from a scan that is launched
        def __init__(self,scanID):
                self.scanID = scanID

        #returns the status of a scan based on the id passed to it
        #can return pending,running,completed, or error
        def scanStatus(self):
                status = requests.get(url+"scans/"+str(self.scanID),headers=headers,verify=True)
                status = status.json()["info"]

                return status['status']

        def downloadResults(self):
                print("downloading...")
