import os
import psutil
import sys
from urllib import urlopen
import urllib2
from bs4 import BeautifulSoup
from Queue import Queue
from threading import Thread, enumerate
from thread import start_new_thread
from time import sleep
import bs4
import logging
import requests
import time
import gc
import mysql.connector
import socket
from tldextract import tldextract
import config
import robotparser


i = 0
index = 0
mem = str(os.popen('free -t -m').readlines())
visited = []
depth = 0
queue = []
myconn = mysql.connector.connect(host="localhost", user="gannu",\
         passwd="gannu", database="DSSE")
cur = myconn.cursor(buffered=True)
f = open("/home/s/Desktop/Information_Security/test.txt", 'a')


# Inserting into database
def inst(pid, url, IP):
    check_url_exhist = "select URLs from Information_Security where URLs = '"+url+"'"
    cur.execute(check_url_exhist)
    check_url_exhist_result = cur.rowcount
    if check_url_exhist_result < 1:
        sql = "INSERT INTO Information_Security (PID, URLs, IPADD) VALUES (%s, %s, %s)"
        print("******************************")
        cur.execute(sql, (pid, url, IP))
        myconn.commit()
    else:
        print("Already there")


def getPID(url):  # Getting PID for URLs
    x = url
    sql = "SELECT SNO FROM Information_Security WHERE URLs = %s"
    cur.execute(sql, (x,))
    myresult = cur.fetchone()
    if myresult is None:
        return  
    else:
        result = myresult[0]
        return result


def upd(IP_Query_result):
    if IP_Query_result is not None:
        flag_update_sql = "UPDATE Information_Security SET Flag = '1' where\
                           URLs = '"+IP_Query_result+"' "
        print(flag_update_sql)
        try:
            pass
            cur.execute(flag_update_sql)
            myconn.commit()
        except Exception as e:
            print(e)


def get_url(url, leng):  # Process for extraction of data and URLs
    PID = getPID(url)
    # print(PID)
    if PID > 0:
        pass
    else:
        ip = IP_add(url)
        inst(-1, url, ip)
        PID = getPID(url)
    global i, index
    index = index+1
    try:
        polite = is_polite(url)
        if polite is True:
            sno_sql = "select SNO from Information_Security where URLs = '"+ url +"'"
            print(sno_sql)
            cur.execute(sno_sql)
            result = cur.fetchone()
            sno = result[0]
            sno = str(sno)
            f.write(url + "\n*************************\n")
            f.close
            req = requests.get(url)
            visited.append(url)
            soup = bs4.BeautifulSoup(req.text, 'html.parser')
            for script in soup(["script", "style"]):
                script.extract()
            i = i+1
            x = soup.get_text()
            hash_x = hash(x)
            hash_update_sql = "UPDATE Information_Security SET H1 = %s  where URLs = %s"
            val = ((hash_x), str(url))
            cur.execute(hash_update_sql, val)
            myconn.commit()
            fn = open("/home/s/Desktop/Information_Security/" + sno + ".txt", "w")
            fn.write(url)
            fn.write(x.encode('utf-8'))
            f1 = open("/home/s/Desktop/Hash_Information_Security/" + sno + ".txt", "w")
            f1.write("%d" %hash_x)
            f1.close()
            n = 0
            for link in soup.find_all('a'):
                l = link.get("href")  # l is the one by one sub links from link
                if l is not None and 'https' in l:
                    if "facebook" in l or "twitter" in l or "instagram" \
                       in l or "linkedin" in l or "flickr" in l or "apple"\
                       in l or "accounts.google" in l or \
                       "support.google" in l or \
                       "play.google" in l or "books.google" in l:
                        pass
                    else:
                        if l not in visited:
                            # appending data into visited list
                            visited.append(l)
                            n = n+1
                            f.write(str(n) + ' ) ' + l + "\n")
                            IP = IP_add(l)
                            inst(PID, l, IP)  # insert func() for sub-urls
                if l is None:
                    pass
                else:
                    pass
        else:
            print(url + " " + "Cannot be fetched")
            pass
    except Exception, e:
        pass
    gc.collect()
    sleep(1)

    sorting_ip(PID, url)


def sorting_ip(PID, url):
    queue.remove(url)
    sql = "select distinct substring_index(IPADD,'.',1) as a,"\
          "substring_index(substring_index(IPADD,'.',2),'.',-1) as b,"\
          "substring_index(substring_index(substring_index\
          (IPADD,'.',3),'.',-1),'.',-1) as c,"\
          "substring_index(IPADD,'.',-1) as d, IPADD  from Information_Security\
          where PID = '"+(str(PID))+"' order by a+0,b+0,c+0,d+0;"

    try:
        cur.execute(sql)
        sql_results = cur.fetchall()
        for element in sql_results:
            ip = element[4]
            result = getUrlsIPBased(ip)
            for url in result:
                P_url = (url[0].encode('utf-8'))
                if P_url not in queue:
                    queue.append(P_url)

    except Exception as e:
        print(e)
    thread_initializer(queue)


def is_polite(url):
    ext = tldextract.extract(url)
    URL = (ext.subdomain + "." + ext.domain + "." + ext.suffix)
    rp = robotparser.RobotFileParser()
    print(rp)
    URL = "https://" + URL + "/robots.txt"
    print(URL)
    rp.set_url(URL)
    rp.read()
    flag = rp.can_fetch("*", url)
    return flag


def getUrlsIPBased(ip):
    sql = "select distinct URLs,IPADD  from Information_Security \
    where IPADD='"+ip+"' and Flag !=1;"
    try:
        cur.execute(sql)
        sql_results = cur.fetchall()
        return sql_results
    except Exception as e:
        print(e)


def IP_add(l):  # extraction of IP address
    ext = tldextract.extract(l)
    URL = (ext.subdomain + "." + ext.domain + "." + ext.suffix)
    ip = socket.gethostbyname(URL)
    return ip


def thread_initializer(queue):
    thrs = []
    # Checking free memory
    T_ind = mem.index('T')
    mem_G = mem[T_ind+14:-4]
    S1_ind = mem_G.index(' ')
    mem_T = mem_G[0:S1_ind]
    mem_G1 = mem_G[S1_ind+8:]
    S2_ind = mem_G1.index(' ')
    mem_U = mem_G1[0:S2_ind]
    mem_F = mem_G1[S2_ind+8:]

    for u1 in queue:
        if u1 is not None and mem_F > 100:
            # initialising of threads
            thr = Thread(target=get_url, args=(u1, len(queue)))
            upd(u1)
            thr.start()
            thr.join()


if __name__ == '__main__':

    sql = "select distinct substring_index(IPADD,'.',1) as a,\
          substring_index(substring_index(IPADD,'.',2),'.',-1) as b,"\
          "substring_index(substring_index\
          (substring_index(IPADD,'.',3),'.',-1),'.',-1) as c,"\
          "substring_index(IPADD,'.',-1) as d, IPADD,pid,urls  from Information_Security \
          where  flag<>1 order by a+0,b+0,c+0,d+0 limit 1;"
    cur.execute(sql)
    result = cur.fetchone()
    if result is not None:
        seed_url = (result[6])
    else:
        seed_url = 'https://en.wikipedia.org/wiki/Information_security'
        print(seed_url)
    queue.append(seed_url)  # Adding seed-url into queue
    upd(seed_url)
    thread_initializer(queue)
