# encoding:utf-8

import requests
from bs4 import BeautifulSoup


def excuteSpider(url,headers,session,):
    req = session.get(url, headers=headers)
    bsObj = BeautifulSoup(req.text, 'html.parser')


    linkList = bsObj.findAll("div", {"class": "righttxt"})
    llinksub=[]


    for link in linkList:
        llinksub.append(link.a['href'].encode('utf-8').decode())
        print (link.a['href'])
    # print llink

    return llinksub


if __name__=='__main__':

    llink=[]

    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0",
           "Accept": "*/*"}
    for i in range(1,21):
        if i==1:
            url = "https://alexa.chinaz.com/Global/"
        else:
            url = "https://alexa.chinaz.com/Global/"+"index_"+str(i)+".html"

        llinksub=excuteSpider(url, headers, session)
        llink+=llinksub


    wf = open('./spider2.csv', 'w')
    wf.write('link\n')
    for i in range(len(llink)):
        wf.write('%s\n' %(llink[i][32:]))
    wf.close()
    print('ok')