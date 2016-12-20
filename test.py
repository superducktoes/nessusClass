from nessusClass import *

if __name__ == '__main__':
    # builds the scan. needs the name and then the host to scan
    testScan = Scan("test scan","172.26.23.85")

    # add additional hosts to be scanned
    testScan.addHosts("172.26.23.86")

    # show the available hosts and policies
    print(testScan.displayHosts())
    print(testScan.showPolicies())

    # set the policy to use based on the policy ID
    testScan.setPolicy(472)

    # shows the policy after setting it
    print(testScan.selectedPolicy())

    # shows the scanners available to be used
    print(testScan.showScanners())

    # sets the scanner to use
    testScan.setScanner(3940)

    # confirm the scan ID set for the scanner to use
    print(testScan.displayScanner())

    # launches the scan and stores the returned scanID
    results = testScan.launchScan()

    # passes the scan id from above to create a new report object
    report = Report(str(results))

    # using that object we can check on the status of the scan
    print(report.scanStatus())

    # once it's complete the scan can be downloaded
    report.downloadResults()
