#!/usr/bin/env python
import time
from zapv2 import ZAPv2

# The URL of the application to be tested
def runspider():
    target = 'https://public-firing-range.appspot.com'
    # Change to match the API key set in ZAP, or use None if the API key is disabled
    apiKey = 'tp4c52en8ll0p89im4eojakbr8'

    # By default ZAP API client will connect to port 8080
    zap = ZAPv2(apikey=apiKey)
    # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
    zap = ZAPv2(apikey=apiKey, proxies={'http': 'https://127.0.0.1:8080/', 'https': 'https://127.0.0.1:8080/'})

    print('Spidering target {}'.format(target))
    # The scan returns a scan id to support concurrent scanning
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        # Poll the status until it completes
        print('Spider progress %: {}'.format(zap.spider.status(scanID)))
        time.sleep(1)

    print('Spider has completed!')
    # Prints the URLs the spider has crawled
    return zap.spider.results(scanID)

res = runspider()
for re in res:
    print(re)