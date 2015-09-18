#!/usr/bin/env python
# -*- coding: utf-8 -*-

from boto.s3.connection import S3Connection
from boto.s3.lifecycle import Lifecycle, Transition, Rule
import sys, getopt, json
from pprint import pprint

def update_lifecycle(*args,**kwargs):
    rules = kwargs['rules']
    config = kwargs['config']
    to_glacier = Transition(days=10, storage_class='GLACIER')
    default_rule = Rule('default-to-glacier', '', 'Enabled', expiration=40, transition=to_glacier)
    try:
        conn = S3Connection(config["aws_access_key_id"], config["aws_secret_access_key"])
    except Exception as err:
        print err
        sys.exit()

    rs = conn.get_all_buckets()
    for b in rs:
        secure = None
        bucket = conn.get_bucket(b)
        elements = bucket.list("", "/")
        lifecycle = Lifecycle()
        for element in elements :
            if element.name == "STATIC/" :
                secure = "YES"
        if secure != None :
            print b.name, " --> PROTECTED"
            for directory in elements :
                if directory.name != "STATIC/":
                    rule_secure = Rule(id="to-glacier-%s" %directory.name.replace("/", "") , prefix="%s" %directory.name, status='Enabled', expiration=40, transition=to_glacier)
                    lifecycle.append(rule_secure)
                else:
                    None
                    #
                    # Traitement dossier STATIC/
                    #
            bucket.configure_lifecycle(lifecycle)
            show_lifecycle(bucket)
        else :
            lifecycle.append(default_rule)
            bucket.configure_lifecycle(lifecycle)
            show_lifecycle(bucket)

def show_lifecycle(bucket):
    print "############# bucket : ", bucket.name
    try:
       current = bucket.get_lifecycle_config()
       for rule in current :
           print "transition : ", rule.transition
           print "expiration : ", rule.expiration
           print "prefix : ", rule.prefix
    except Exception:
       print "No Lifecycle configuration"

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"hr:c:", ["help", "rules", "config"])
        print opts
        if not opts:
            usage()
    except getopt.GetoptError:
        usage()
    aws = None
    data = None
    for opt, arg in opts:
        if opt == '-h':
            usage()
        #elif opt in ("-r", "--rules"):
        #    rules_file = arg
        #    with open(rules_file) as data_file:    
        #        data = json.load(data_file)
        #        pprint(data)
        elif opt in ( "-c", "--config"):
            aws_file = arg
            with open(aws_file) as aws_cred:    
                aws = json.load(aws_cred)
        #        pprint(aws)
    #if aws is None or data is None :
    #    usage()
    update_lifecycle(rules=data, config=aws)

def usage():
    #print "\n ./update_lifecyle_rules.py -r path_to_rules_file.json -c path_to_aws_credentials_file\n"
    print "\n ./update_lifecyle_rules.py -c path_to_aws_credentials_file\n"
    sys.exit()

if __name__ == "__main__":
   main(sys.argv[1:])
