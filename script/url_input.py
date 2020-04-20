import os
import csv
url_list = []

with open('sites_50.csv','rb') as myFile:
    lines=csv.reader(myFile)
    for line in lines:
        #print line[0]
        url_list.append(line[0])
#url_list = url_list[416: ]
url_list.remove("link")
print url_list

with open("result.csv","a") as csvfile: 
    writer = csv.writer(csvfile)
    writer.writerow(["website","time1","total1","time2","total2","time3","total3","time4","total4","time5","total5","time6","total6","time7","total7","time8","total8","time9","total9","time10","total10","timeavg", "totalavg"])
    #writer.writerow(["website","time1","total1","time2","total2","time3","total3","time4","total4","time5","total5","timeavg", "totalavg"])

    for url in url_list:
        tmp_list = []
        tmp_list.append(url)
        timeavg = 0.0
        totalavg = 0.0
        print url
        cmd = "curl -s -H \"Content-Type: application/json\" -X POST http://0.0.0.0:5000/generate -d \'{\"target\": \"" + url + "\"}\'"
        for i in range(10):
            fouput = os.popen(cmd)
            result = fouput.readlines()
            print result[0]
            resList = result[0].split("time1: ")
            #print(resList[0])
            #tmp_list.append(resList[0])
            if len(resList) > 1:
                respms = resList[1].split("time: ")
                print(respms[0])
                timeavg = timeavg + float(respms[0])
                tmp_list.append(respms[0])
                print(respms[1])
                totalavg = totalavg + float(respms[1])
                tmp_list.append(respms[1])
            else:
                tmp_list.append(0.0)
                tmp_list.append(0.0)
            tmp_list.append(timeavg/10.0)
            tmp_list.append(totalavg/10.0)
        writer.writerow(tmp_list)
    '''
fouput = os.popen("curl -s -H \"Content-Type: application/json\" -X POST http://0.0.0.0:5000/generate -d \'{\"target\": \"google.com\"}\'")
result = fouput.readlines()
print("result is: %s" % result)
resList = result[0].split("time: ")
print(resList[1])'''