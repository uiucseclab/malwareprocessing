# -*- coding: utf-8 -*-
"""
Created on Fri Feb 07 12:09:19 2014

@author: kocinsk2, kmcclel2
"""

import imaplib
import re
import urllib2
import zipfile
import cgi
import ftplib
import postfile
import os
import sys


def grabFile(raw, sort):
    #Regex to parse out URLs
    x = re.compile(r"http://(\w*[.])*(\w*/)*(\w*[-]\w*)*[?]\w*(\w*[-]\w*)*")
     
    url = x.search(raw).group()
    print "URL found\n"
    #print url
    
    #Open URL and grab filename
    print "Searching URL for filename\n"
    zfile = urllib2.urlopen(url)
    _,params = cgi.parse_header(zfile.headers.get('Content-Disposition', ''))
    filename = params['filename']
    print "Filename found\n"
    
    #Download the file
    print "Beginning File Download\n"
    data = zfile.read()
    print type(data)
    with open(filename, "wb") as code:
        code.write(data)
    print "Download Complete\n"
    
    #Unzip the file
    print "Unzipping file\n"
    with zipfile.ZipFile(filename, "r") as z:
        z.extractall()
    print "Unzip Complete\n"
    
    
    #Upload the file to vxcage
    # UNTESTED CODE CORRECT IN THEORY
    pathname = '/malware/'+sort+'/'+md5(fopen(filename))
    scpquery = 'scp ' + filename + ' intake@vxcage.internetcrimefighter.org:' + pathname
    os.system(scpquery)
    
    #Upload the file to virus total
    print "Uploading to virus total\n"
    host = "www.virustotal.com"
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", "")]
    file_to_send = open(filename, "rb").read()
    files = [("file", filename, file_to_send)]
    json = postfile.post_multipart(host, selector, fields, files)
    print "Upload successful\n"
    
    
    #Upload the file to totalhash
    print "Beginning FTP uplaod to totalhash"
    ftpserver = '198.100.146.47' #totalhash.com
    session = ftplib.FTP(ftpserver,'upload','totalhash')
    f = open(filename,'rb')                  # file to send
    session.storbinary(filename, f)     # send the file
    f.close()                                    # close file and FTP
    session.quit()
    print "Upload complete"

def main():
    if len(sys.argv) == 2:
        subject = sys.argv[1]
        
    else:   
        print '[-] Usage: ' + str(sys.argv[0]) +\
        ' <subject line search term>'
        exit(0)
            
    #Email Information
    account = "cs460zipdump@gmail.com"
    password = "Class-Test-2014"
    
    #Login to gmail and enter inbox
    print "Logging into mail account\n"
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(account, password)
    print "Login Successful\n"
    mail.list()
    mail.select("inbox")
    
    #Grab Email Bodies
    print "Grabbing Email body to parse for URL\n"
    '''
    charset, data = mail.uid('search', None, "ALL")
    recentUnreadID = data[0].split()[-1]
    charset, data = mail.uid('fetch', recentUnreadID, '(RFC822)')
    raw_mail = data[0][1]
    '''
    typ, data = mail.search(None, subject, "ALL")
    for num in data[0].split():
        typ, data = mail.fetch(num, '(RFC822)')
        grabFile(data[0][1], subject)
    mail.close()
    mail.logout()
    
if __name__ == '__main__':
    main()

