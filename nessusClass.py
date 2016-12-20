import json
import requests

#replace these with the keys for the account used for scanning
accessKey = ""
secretKey = ""

url = "https://cloud.tenable.com/"
headers = {'X-ApiKeys': 'accessKey=' + str(accessKey) + '; secretKey = ' + str(secretKey) + ';'}

class Scan:

        # Scan - Used for building and launching scans. Does not take any attributes when creating the class.
        # - Requires scan name and host to build class
        # use launchScan() to run the scan after setting the name, hosts, policy, and scanner to use.
                
        def __init__(self,name,hosts):
                self.name = name
                self.hosts = hosts

        # shows a current list of hosts to be scanned
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

        # sets the policy to use based on ID. If the policy does not exist it returns false.
        def setPolicy(self,policyID):
                policyExists = requests.get(url+"policies/"+str(policyID),headers=headers,verify=True)
                
                if(policyExists.status_code == 200):
                        self.policy = policyID
                        status = True
                else:
                        status = False

                return status

        # returns the policy id to be used with the scan.
        def selectedPolicy(self):
                return self.policy

        # returns a list of available scanners
        def showScanners(self):
                scanners = requests.get(url+"scanners/",headers=headers,verify=True)
                listScanners = scanners.json()["scanners"]
                return listScanners

        #sets the scanner to use based on the id. returns false if the scanner does not exist.
        def setScanner(self,scannerID):

                scannerExists = requests.get(url+"scanners/"+str(scannerID),headers=headers,verify=True)

                if(scannerExists.status_code == 200):
                        self.scannerID = scannerID
                        status = True
                else:
                        status = False

                return status

        # returns the id of the scnaner to use for the scan
        def displayScanner(self):
                return self.scannerID

        # used to change the name of the scan set by the constructor
        def updateScanName(self,name):
                self.scanName = name

        # returns the name set of the scan
        def displayScanName(self):
                return self.scanName

        # used to launch the scan once the policy, scanner, hosts, and name are set
        # returns the uuid of the scan launched
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
                self.downloadType = "nessus"
                
        #returns the status of a scan based on the id passed to it
        #can return pending,running,completed, or error
        def scanStatus(self):
                status = requests.get(url+"scans/"+str(self.scanID),headers=headers,verify=True)
                status = status.json()["info"]

                return status['status']
        
        # returns False if not set to one of the three file format types
        def setDownloadType(self,download):
                download = (download.lower())
                if(download == "nessus" or download == "pdf" or download == "html"):
                        self.downloadType = download
                        status = True
                else:
                        status = False

                return status
        
        # downloads the results of the file. Scan needs to be in the completed status before it can be downloaded.
        # this is a two part process that needs both the scanID which is returned from the scan and the fileID which is
        # obtained below. These two ID's are needed to download the actual results.
        #
        # unless otherwise modified the default download type is in the .nessus format.
        
        def downloadResults(self):
                
                report = {"scan_id":self.scanID,
                          "format":self.downloadType
                          }

                fileID = requests.post(url+"scans/"+str(self.scanID)+"/export",json=report,headers=headers,verify=True)
                fileID = fileID.json()
                # this is first half that prepares the int that combines the scan id and report type
                fileID = fileID["file"]
                print(fileID)

                # now we can download the file using the above id
                reportResult = requests.get(url+"scans/"+str(self.scanID)+"/export/"+str(fileID)+"/download",
                                            headers=headers,
                                            verify=True)
                return reportResult

class Policy:

        # empty lists to store username/passowrd
        windowsUsers = []
        windowsPasswords = []
        linuxUsers = []
        linuxPasswords = []
        # empty dict that combines the list at the end
        windowsCredentials = {}
        linuxCredentials = {}
        
        def __init__(self,name):
                self.name = name
                self.webapps = "no"
                self.timeout = "5"
                self.pingHost = "yes"

        # adds the username/password sets for windows hosts
        def addWindowsCreds(self,username,password):
                Policy.windowsUsers.append(str(username))
                Policy.windowsPasswords.append(str(password))

        # adds the username/passwords sets for linux hosts
        def addLinuxCreds(self,username,password):
                Policy.linuxUsers.append(str(username))
                Policy.linuxPasswords.append(str(password))

        # combines each of the creds lists into dict's for the policy
        def buildCredentials(self):
                windowsCredentials = dict(zip(Policy.windowsUsers,Policy.windowsPasswords))
                linuxCredentials = dict(zip(Policy.linuxUsers,Policy.linuxPasswords))
                print(windowsCredentials)
                
        # used to set whether or not to run web app tests. by default the option is set to no.
        # returns False if yes or no is not set for the option
        def setScanWebApps(self,choice):
                choice = (choice.lower())

                if(choice == "yes" or choice == "no"):
                        self.webapps = choice
                        status = True
                else:
                        status = False

                return status

        def pingRemoteHost(self,choice):
                choice = (choice.lower())
                
                if(choice == "yes" or choice == "no"):
                        self.pingHost = choice
                        status = True
                else:
                        status = False
                        
                        return status
                
        # used to set the network timeout variable. takes an int. returns false if not an int. default set to 5
        def setNetworkTimeout(self,choice):
                if(choice.is_integer()):
                        self.timeout = str(timeout)
                        status = True
                else:
                        status = False

                return status
        
        # call this last to save the policy
        # returns the id of the policy created.
        def savePolicy(self):
                print("saves the policy")
