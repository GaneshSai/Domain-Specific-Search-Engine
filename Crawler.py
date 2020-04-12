import os
import psutil
import sys
import urllib3
from bs4 import BeautifulSoup
import queuelib
from threading import Thread
from time import sleep
import bs4
import logging
import requests
import time
import gc
import mysql.connector
import configparser
from config import DatabaseConfig
from config import FilesConfig
from config import UnwatedUrlsConfig
from config import PoliteConfig
import re
from w2vec import *
import json
import socket
from tldextract import tldextract
import ssl

index = 0
mem = str(os.popen("free -t -m").readlines())
visited = []
depth = 0
queue = []

w2v_model_300 = KeyedVectors.load_word2vec_format("model300.bin", binary=True)
print("Model 300 loaded")

myconn = mysql.connector.connect(
    host=DatabaseConfig.host,
    user=DatabaseConfig.user,
    passwd=DatabaseConfig.passwd,
    database=DatabaseConfig.database,
)

cur = myconn.cursor(buffered=True)
f = open(FilesConfig.sub_urls, "a")


# Inserting into database
def inst(pid, url, IP):
    check_url_exhist = (
        "select URLs from Information_Security1 where URLs = '" + url + "'"
    )
    cur.execute(check_url_exhist)
    myconn.commit()
    check_url_exhist_result = cur.rowcount
    if check_url_exhist_result < 1:
        sql = "INSERT INTO Information_Security1\
              (PID, URLs, IPADD) VALUES (%s, %s, %s)"
        cur.execute(sql, (pid, url, IP))
        myconn.commit()
    else:
        pass


# Getting PID for URLs
def getPID(url):
    x = url
    sql = "SELECT SNO FROM Information_Security1 WHERE URLs = %s"
    cur.execute(sql, (x,))
    myconn.commit()
    myresult = cur.fetchone()
    if myresult is None:
        myresult = 0
        result = myresult
        return result
    else:
        result = myresult[0]
        print(result)
        return result


# Updating visited url in database to 1
def upd(IP_Query_result):
    if IP_Query_result is not None:
        flag_update_sql = ""
        try:
            flag_update_sql = """UPDATE Information_Security1 SET Flag = '1' where
                           URLs = '{IP_Query_result}' """.format(
                IP_Query_result=IP_Query_result.decode()
            )
        except Exception as e:
            flag_update_sql = """UPDATE Information_Security1 SET Flag = '1' where
                           URLs = '{IP_Query_result}' """.format(
                IP_Query_result=IP_Query_result
            )
        try:
            pass
            cur.execute(flag_update_sql)
            myconn.commit()
        except Exception as e:
            print(e)
            # pass


# Process for extraction of data and URLs
def get_url(url, leng):
    PID = getPID(url)
    if PID == 0:
        ip = IP_add(url)
        inst(-1, url, ip)
        PID = getPID(url)
    else:
        PID = getPID(url)
    global index
    index = index + 1
    polite_flag = PoliteConfig.POLITE_FLAG
    polite = PoliteConfig().is_polite(url)
    if polite_flag is False:  # Force crawling of URL if needed.
        polite = True
    if polite is True:
        crawling(url, PID)
    else:
        pass


def crawling(url, PID):
    try:
        print(url)
        sno_sql = "select SNO from Information_Security1 where URLs = '" + url + "'"
        cur.execute(sno_sql)
        result = cur.fetchone()
        sno = result[0]
        print(sno)
        sno = str(sno)
        f.write(url + "\n*************************\n")
        f.close
        req = requests.get(url)
        visited.append(url)
        soup = bs4.BeautifulSoup(req.text, "html.parser")
        for script in soup(["script", "style"]):
            script.extract()
        text = soup.get_text()
        hash_x = hash(text)
        hash_update_sql = "UPDATE Information_Security1 SET H1 = %s  where URLs = %s"
        val = ((hash_x), str(url))
        cur.execute(hash_update_sql, val)
        myconn.commit()
        fn = open(FilesConfig.text_storing + sno + ".txt", "w")
        fn.write(url)
        fn.write(text)
        f1 = open(FilesConfig.hash_value + sno + ".txt", "w")
        f1.write("%d" % hash_x)
        f1.close()
        w2v_sim(url, text)
        n = 0
        for link in soup.find_all("a"):
            sub_link = link.get("href")  # sub_link is the one by one sub links from link
            if sub_link is not None and "https" in sub_link:
                for x in UnwatedUrlsConfig.web_sites:
                    x = UnwatedUrlsConfig.web_sites.encode("ascii")
                    web_sites = json.loads(x)
                    res = any(ele in sub_link for ele in web_sites)
                    if res is True:
                        pass
                    else:
                        if sub_link not in visited:
                            # appending data into visited list
                            visited.append(sub_link)
                            n = n + 1
                            f.write(str(n) + " ) " + sub_link + "\n")
                            IP = IP_add(sub_link)
                            inst(PID, sub_link, IP)  # insert func() for sub-urls
            if sub_link is None:
                pass
            else:
                pass
    except Exception as e:
        pass
    gc.collect()
    sleep(1)

    sorting_ip(PID, url)


def sorting_ip(PID, url):
    print(PID)
    queue.remove(url)
    sql = (
        "select distinct substring_index(IPADD,'.',1) as a,"
        "substring_index(substring_index(IPADD,'.',2),'.',-1) as b,"
        "substring_index(substring_index(substring_index\
          (IPADD,'.',3),'.',-1),'.',-1) as c,"
        "substring_index(IPADD,'.',-1) as d, IPADD  from Information_Security1\
          where PID = '"
        + (str(PID))
        + "' order by a+0,b+0,c+0,d+0;"
    )
    print(sql)
    try:
        cur.execute(sql)
        myconn.commit()
        sql_results = cur.fetchall()
        print(sql_results)
        for element in sql_results:
            ip = element[4]
            result = getUrlsIPBased(ip)
            for url in result:
                P_url = url[0]
                if P_url not in queue:
                    queue.append(P_url)

    except Exception as e:
        print(e)
    thread_initializer(queue)


def getUrlsIPBased(ip):
    sql = (
        "select distinct URLs,IPADD  from Information_Security1 \
    where IPADD='"
        + ip
        + "' and Flag !=1;"
    )
    try:
        cur.execute(sql)
        myconn.commit()
        sql_results = cur.fetchall()
        return sql_results
    except Exception as e:
        print(e)


def IP_add(l):  # extraction of IP address
    ext = tldextract.extract(l)
    URL = ext.subdomain + "." + ext.domain + "." + ext.suffix
    ip = socket.gethostbyname(URL)
    return ip


def thread_initializer(queue):
    thrs = []
    # Checking free memory
    T_ind = mem.index("T")
    mem_G = mem[T_ind + 14:-4]
    S1_ind = mem_G.index(" ")
    mem_T = mem_G[0:S1_ind]
    mem_G1 = mem_G[S1_ind + 8:]
    S2_ind = mem_G1.index(" ")
    mem_U = mem_G1[0:S2_ind]
    mem_F = mem_G1[S2_ind + 8:]
    mem_F = int(mem_F)

    for u1 in queue:
        if u1 is not None and mem_F >= 100:
            # initialising of threads
            thr = Thread(target=get_url, args=(u1, len(queue)))
            upd(u1)
            thr.start()
            thr.join()


if __name__ == "__main__":

    sql = (
        "select distinct substring_index(IPADD,'.',1) as a,\
          substring_index(substring_index(IPADD,'.',2),'.',-1) as b,"
        "substring_index(substring_index\
          (substring_index(IPADD,'.',3),'.',-1),'.',-1) as c,"
        "substring_index(IPADD,'.',-1) as d, IPADD,pid,urls  from Information_Security1 \
          where  flag<>1 order by a+0,b+0,c+0,d+0 limit 1;"
    )
    cur.execute(sql)
    myconn.commit()
    result = cur.fetchone()
    if result is not None:
        seed_url = result[6]
    else:
        seed_url = "https://en.wikipedia.org/wiki/Information_Security"
        print(seed_url)
    queue.append(seed_url)  # Adding seed-url into queue
    upd(seed_url)
    thread_initializer(queue)
