#! /usr/bin/python

import sys
import subprocess
import optparse
import threading
from neo4jrestclient.client import GraphDatabase
from getpass import getpass
from time import sleep


def create_session():
    '''
    Gets IP of server & returns session token
    '''
    neoip = "0"
    neoip = raw_input('Enter IP of neo4j DB or press [ENTER] for localhost: ')
    if neoip == '':
        print "Using 'localhost' "
        neoip = 'localhost'
    neoun = "0"
    neoun = raw_input('Enter neo4j DB username or press [ENTER] for neo4j: ')
    if len(neoun) == 0:
        neoun = "neo4j"
    addr = 'https://' + neoip + ':7473/db/data/'
    gdb = GraphDatabase(addr, username=neoun, password=getpass('Enter neo4j password: '))
    return gdb

def main():
    '''
    VDNS was written to be included in the MercenaryHuntFramework  and on Mercenary-Linux
    It can however be run as a standalone application.  This application requires that bro-cut
    be installed on the host. Default location that it looks for bro-cut is /usr/local/bro/bin/bro-cut
    If your installation path for bro-cut is different, modify the sourcefile accordingly.
    '''

    # Handle command-line arguments
    PARSER = optparse.OptionParser()
    PARSER.add_option('--logfile', default=None, help='Logfile to read from.  Default: %default')
    (options, args) = PARSER.parse_args() #changed Feb2017 Throwing error for unknown var OPTIONS

    gdb = create_session()
    # Create a BRO log file reader and pull from the logfile
    full_query = "cat {0} | /usr/local/bro/bin/bro-cut uid id.orig_h id.orig_p\
            id.resp_h id.resp_p query answers qtype_name ".format(options.logfile)

    # ___ Fails the first time even after the NUll node is added____
    dnsquery = gdb.labels.create("DNS_COMMS") #create label
    queries = gdb.labels.create("DNS_QUERIES") #create label
    answers = gdb.labels.create("DNS_ANSWERS") #create label
    qtypes = gdb.labels.create("DNS_QTYPES") #create label
    dns_Sips = gdb.labels.create("DNS_SOURCE_IPS") #create label
    dns_Dips = gdb.labels.create("DNS_DEST_IPS") #create label
    print "[+] Creating Labels..."
    sleep(5)

    nval = gdb.node.create(query="NULL") #create null node
    nval.labels.add('DNS_QUERIES') #initialize node label w/ null node
    nval2 = gdb.node.create(uid = 'NULL', s_ip = 'NULL', d_ip = 'NULL', s_port = 'NULL', d_port = 'NULL', qtype = 'NULL', query = 'NULL', answer="NULL") #create node
    nval2.labels.add('DNS_COMMS')#initialize node label w/ null node
    nval3 = gdb.node.create(qtype="NULL") #create node
    nval3.labels.add('DNS_QTYPES') #initialize node label w/ null node
    nval4 = gdb.node.create(answer="NULL") #create node
    nval4.labels.add('DNS_ANSWERS') #initialize node label w/ null node
    nval5 = gdb.node.create(s_ip="NULL") #create node
    nval5.labels.add('DNS_SOURCE_IPS') #initialize node label w/ null node
    nval6 = gdb.node.create(d_ip='NULL')
    nval6.labels.add('DNS_DEST_IPS')
    p = subprocess.Popen(full_query, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    cnt = 0 #Counter to Track Number of Entries based on threads created to ingest them
    for line  in p.stdout.readlines():
        lline = line.split()
        for val in range(len(lline)):
            if ',' in lline[val]:
                lline2 = lline[val].split(',')
            else:
                lline2 = lline[val]
            if (val == 0):
                v1 = lline2
            elif (val ==1): #Source IP
                v2 = lline2
                srclist = gdb.labels.get('DNS_SOURCE_IPS') # handle on query transaction for nodes w/ matchng label
                check = srclist.get(s_ip=lline2) #check nodes for existence of value of lline2
                if (len(check) == 0): # If no query  matches a query already under label
                    hsrc = gdb.nodes.create(s_ip=lline2)
                    dns_Sips.add(hsrc)
            elif (val == 2):
                v3 = lline2
            elif (val == 3): #Dest IP
                v4 = lline2
                dstlist = gdb.labels.get('DNS_DEST_IPS') # handle on query transaction for nodes w/ matchng label
                check = dstlist.get(d_ip=lline2) #check nodes for existence of value of lline2
                if (len(check) == 0): # If no query  matches a query already under label
                   hdst = gdb.nodes.create(d_ip=lline2)
                   dns_Dips.add(hdst)
            elif (val == 4): #Dest Port
                v5 = lline2
            elif (val == 5): #Query
                v6 = lline2
                querylist = gdb.labels.get('DNS_QUERIES') #get handle on query transaction for all nodes for the DNS_QUERY LABEL
                check = querylist.get(query=lline2)
                if (len(check) == 0): # If no query matches a query already under DNS_QUERIES label
                    hquery = gdb.nodes.create(query=lline2)
                    queries.add(hquery)
            elif (val == 6): #Answers
                v7 = lline2
                anslist = gdb.labels.get('DNS_ANSWERS') #get handle on query tansaction for all nodes with DNS_ANSWERS label
                check = anslist.get(answer=lline2)
                if (len(check) == 0): #If no query matches a query already under DNS_ANSWERS label
                    hanswer = gdb.nodes.create(answer=lline2)
                    answers.add(hanswer)
            elif (val == 7): #QueryType
                v8 = lline2
                qtlist = gdb.labels.get('DNS_QTYPES') #get handle on query transaction for all nodes with DNS_QUERY label
                check = qtlist.get(qtype=lline2)
                if (len(check) == 0): #If no query matches a query already under DNS_QTYPES label
                    hqtype = gdb.nodes.create(qtype=lline2) #Create Node and return handle to Node
                    qtypes.add(hqtype) #Use Handle to Label DNS_QTYPES to add node using the handle to the node
            else:
                pass
        
        q = gdb.nodes.create(uid=v1, s_ip=v2, s_port=v3, d_ip=v4, d_port=v5, query=v6, answer=v7, qtype=v8)
        new_thread = threading.Thread(dnsquery.add(q))
        new_thread.start()
        new_thread.join
        cnt += 1
        print "[+] {0} DNS Log Entries Injested".format(cnt)

if __name__ == '__main__':
    #parse args from cli
    if len(sys.argv) < 2:
        print "Error: Too Few Arguments"
        print "<command> --help"
        sys.exit()
        
    main()
