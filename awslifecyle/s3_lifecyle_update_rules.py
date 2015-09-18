#!/usr/bin/env python
# -*- coding: utf-8 -*-

from boto.s3.connection import S3Connection
from boto.s3.lifecycle import Lifecycle, Transition, Rule
import sys, getopt, json

def update_lifecycle(*args,**kwargs):
    rules = kwargs['rules']
    config = kwargs['config']
    default_to_glacier = Transition(days=7, storage_class='GLACIER')
    default_rule = Rule('default-to-glacier', '', 'Enabled', expiration=20, transition=default_to_glacier)
    aps_to_glacier = Transition(days=14, storage_class='GLACIER')
    aps_rule = Rule('default-aps-to-glacier', '', 'Enabled', expiration=180, transition=aps_to_glacier)
    try:
        conn = S3Connection(config["aws_access_key_id"], config["aws_secret_access_key"])
    except Exception as err:
        print err
        sys.exit()

    rs = conn.get_all_buckets()
    for b in rs:
        secure = None
        bucket = conn.get_bucket(b)
        if "aps" in b.name:
            rule_to_use = aps_rule
            expiration_to_use = 180
            transition_to_use = aps_to_glacier
        else:
            rule_to_use = default_rule
            expiration_to_use = 20
            transition_to_use = default_to_glacier
        elements = bucket.list("", "/")
        lifecycle = Lifecycle()
        for element in elements :
            if element.name == "STATIC/" :
                secure = "YES"
        if secure != None :
            print b.name, " --> PROTECTED"
            for directory in elements :
                if directory.name != "STATIC/":
                    rule_secure = Rule(id="to-glacier-%s" %directory.name.replace("/", "") , prefix="%s" %directory.name,
                            status='Enabled', expiration=expiration_to_use, transition=transition_to_use)
                    lifecycle.append(rule_secure)
        else :
            lifecycle.append(rule_to_use)
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
        opts, args = getopt.getopt(argv,"hc:", ["help", "config"])
        print opts
        if not opts:
            usage()
    except getopt.GetoptError:
        usage()
    aws = None
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ( "-c", "--config"):
            aws_file = arg
            with open(aws_file) as aws_cred:    
                aws = json.load(aws_cred)
    if aws is None :
        usage()
    update_lifecycle(config=aws)

def usage():
    print "\n ./s3_lifecyle_update_rules.py -c path_to_aws_credentials_file\n"
    sys.exit()

if __name__ == "__main__":
   main(sys.argv[1:])
