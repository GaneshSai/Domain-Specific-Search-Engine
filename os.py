import bs4
import requests
def isLink(url):
    try:
        req = requests.get(url)
#    print ("hello")
    
    #
        soup = bs4.BeautifulSoup(req.text, 'html.parser')
    
# for link in soup.find_all('a'):
#         l = link.get("href")
#         if l is None:
#             continue
#         else:
#             correctlink(l)
# def correctlink(l):
#    if "https://" in l: 
#
        # all_text = ''.join(soup.findAll(text=True))
        # print (all_text)
        i=0
        fname=""
        for script in soup(["script", "style"]): 
            script.extract()
        i=i+1
        fname="/home/ganesh/test/text"+str(i)+".txt"
        f = open(fname, "w")
        f.write(soup.get_text())
        f.close()
    except:
        pass
def on_timeout(self):
    time.sleep(100)
    return True
    
with open('fullurls.txt') as fp:
    for line in fp:
        # print (line)
        # for ch in "[,]":
        #     line = line.replace(ch,'"')
        #     for ch in "',\t, ":
        #         line = line.replace(ch,'')
        url = (line)
        isLink(url)     
        
#             print (type(url))
# url = "https://t.co/rB2F95v7Sy"
# isLink(url)