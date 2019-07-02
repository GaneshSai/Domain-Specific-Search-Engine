from tweepy.streaming import StreamListener
from tweepy import OAuthHandler
from tweepy import Stream
import tweepy
from http import HTTPStatus
# from http import utils
import bs4
import re
import json


access_token = "2540742692-sdeUxnWMYfhWmhZZ5Y7RhbSC8SRHqPi7O01HHPn"
access_token_secret = "6cKAB7i9d8ZySc0T48KjbTjEh6SMpUglQR5txnqXdJEfm"
consumer_key = "sQsLJRptdVB34wWVd24nnyYab"
consumer_secret = "rULlYhw5dlG8xFLvLrbTnbFmCKNVmiL2CmyzlIsGHD31lVPn2A"

class StdOutListener(StreamListener):

    def on_data(self, data):
        data = json.loads(data)
        # print(data)
        x = data['text']
        try:
            urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', x)
            file = open("twitter.txt","a")
            file.write("%s\n" % urls)
            file.close()
        except:
            pass
        
        return True
        
    def on_error(self, status):
        print (status)

    def on_timeout(self):
        time.sleep(100)
        return True


if __name__ == '__main__':

    l = StdOutListener()
    auth = OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    stream = Stream(auth, l)


    stream.filter(track=["Desk Information Security", "Access Information Security","Fire Extinguisher Information Security", "Emergency Information Security", "Lightning resister Information Security", 
     "Lock Information Security", "Power Information Security", "Location Information Security", "Surveillance Information Security",
     "Monitor Information Security", "Heating Ventillation Airconditioning Information Security", 
     "Alarm Information Security", "Floor Information Security", "Ceiling Information Security", "Rack Information Security","Server Security", "Storage Security", "Alert Information Security", "Monitor Information Security", "Asset Information Security", "Incident Information Security","Policy Information Security", "People Information Security",
     "Standard Information Security", "Procedure Information Security", "Governance Information Security",
    "Contract Information Security", "Law Information Security", "Intellectual Property Rights Information Security",
    "Metrics Information Security", "Testing Information Security", "Certificate Information Security",
     "Compliance Information Security", "Regulation Information Security", "Business Continuity Information Security","Firewall ", "Network Time Protocol Security","Virtual Private Network ", "VPN", "Open Systems Interconnect Security", "Topology Security", "Throughput Security", "Bandwidth Security", "Local Area Network Security", "LAN Security", "Wide Area Network Security", "WAN Security", "Virtual Local Area Network Security", "Demilitarized zone  Network Security", "Domain Name System Security", "Internet Protocol V4 Security","Internet Protocol V6 Security", "IP Security", "IPV4 Security", "IPV6 Security", "Wireless Security","Internet Security", "Switch Network Security", "Router Network Security", "Multiplexer Network Security","Operating System Security", "Data Security", "Web Security", "Code Application Security", "Web Application Firewall", "Middle Tier Security","Account Security", "Authorization Security", "Authentication Security", "Cryptography","Computer Information Security", "Desktop Information Security","Laptop Information Security", "Thin Client Information Security", "Mobile Device Security",    "Projector Information Security", "Printer Information Security", "Keyboard Information Security",       "Mouse Information Security", "USB Information Security", "Anti-virus","IaaS Security", "PaaS Security", "SaaS Security","Virtualization  Security", "Virtual Private Cloud", "VPC  Security ","Crime Cyber", "Cyber Squatter", "Cyber Security", "Social Engineering Cyber", "Safety Cyber","deceptive software", "Injection Information",
         "Tampering Information", "Repudiation Security", "Information disclosure", "hacking", "hactivism",
        "adware", "spyware", "trojan Security", "zombie Security", "denial of service", "DOS attack", 
        "Distributed Denial of Service", "DDOS attack", "Cross site scripting", "XSS", "Cross Site Request Forgery",
        "CSRF", "Buffer overflow", "sniffer Information Security", "spam", "spoofing", "Groupware", "Phishing",
         "Smishing", "Vishing", "ransomware", "malware", "botnet"])
