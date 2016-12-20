from nessusClass import *

if __name__ == '__main__':
    testScan = Scan("test scan","172.26.23.85")
    testScan.addHosts("172.26.23.86")
#    print(testScan.displayHosts())
#    print(testScan.showPolicies())
    testScan.setPolicy(472)
#    print(testScan.selectedPolicy())
#    print(testScan.showScanners())
    testScan.setScanner(3940)
#    print(testScan.displayScanner())
    results = testScan.launchScan()
    print(results)

    report = Report(str(results))
    print(report.scanStatus())
