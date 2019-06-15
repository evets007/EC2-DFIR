import boto3
import pprint
import time
import json
import csv
import os
#pp = pprint.PrettyPrinter(indent=2)

##INIT CONNECTION###
def init(case_id,aws_access_key_id,aws_secret_access_key,target_ip,pref_region):
    client = boto3.client('cloudtrail',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,region_name=pref_region);
    s3_client = boto3.client('s3',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,region_name=pref_region)
    s3_resource = boto3.resource('s3',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,region_name=pref_region)
    logs(case_id,client,s3_client,s3_resource,target_ip)
##GLOBAL##
#ocal = 'Cloudtrails'
#bucket = 'forensic-test-001'


def download_dir2(prefix, local, bucket,
                 s3_client, s3_resource):
    print('Downloading cloudtrail logs, Please wait...')
    keys = []
    dirs = []
    next_token = ''
    base_kwargs = {
        'Bucket':bucket,
        'Prefix':prefix,
    }
    while next_token is not None:
        kwargs = base_kwargs.copy()
        if next_token != '':
            kwargs.update({'ContinuationToken': next_token})
        results = s3_client.list_objects_v2(**kwargs)
        contents = results.get('Contents')
        for i in contents:
            k = i.get('Key')
            if k[-1] != '/':
                keys.append(k)
            else:
                dirs.append(k)
        next_token = results.get('NextContinuationToken')
    for d in dirs:
        dest_pathname = os.path.join(local, d)
        if not os.path.exists(os.path.dirname(dest_pathname)):
           os.makedirs(os.path.dirname(dest_pathname))
    for k in keys:
        dest_pathname = os.path.join(local, k)
        if not os.path.exists(os.path.dirname(dest_pathname)):
            os.makedirs(os.path.dirname(dest_pathname))
        s3_resource.meta.client.download_file(bucket, k, dest_pathname)

#case_id = input("Please enter case ID...")
#if not os.path.exists(case_id):
#    os.makedirs(case_id)

def logs(case_id,client,s3_client,s3_resource,target_ip):
    print('Checking CloudTrails available on account...\n')
    ch = input("Do you want to download all cloudtrails found in the account(if any)? y/n >>")
    print('\tName-\t\t-S3 Bucket-\t\t-Region-\t-Global Logging')
    local = './cases/'+case_id
    prefix = 'AWSLogs/'
    response = client.describe_trails()
    for item in response['trailList']:
        print("\t{0}\t{1}\t{2}\t{3}".format(item['Name'],item['S3BucketName'],item['HomeRegion'],item['IsMultiRegionTrail']))
        has_trails = True
        bucket = item['S3BucketName']
        if(ch=='y'):
            download_dir2(prefix,local,bucket,s3_client,s3_resource)

    print('\nSearching events triggered from compromised instance IP...')
    print('\n-Source IP-\t\t-UserAgent-\t-Event ID-\t-AWS Username-\t-Event-\n')
    response = client.lookup_events(MaxResults=1000)
    for line in response['Events']:
        if target_ip in line['CloudTrailEvent']:
            p = line['CloudTrailEvent']
            x = json.loads(p)
            print('{0}\t{1}\t{2}\t{3}\t{4}\t'.format(x['sourceIPAddress'],x['userAgent'],x['eventID'],x['userIdentity']['userName'],x['eventName']))

    p = dict(response)
    with open('./cases/'+case_id+'/all_events.json', 'w+') as out_file:
        json.dump(p, out_file, sort_keys = True, indent = 4,
               ensure_ascii = False, default=str)
    print('Written event logs to cases/'+case_id+'/all_events.json')
