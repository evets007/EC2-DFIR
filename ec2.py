##REF https://www.sans.org/reading-room/whitepapers/cloud/digital-forensic-analysis-amazon-linux-ec2-instances-38235
##
import sys
import boto3
import pprint
import time
import json
import csv
import sys
import os
#from configuration import *
from ssh import *
from cloudtrail import *
from pathlib import Path
###GLOBAL####
pp = pprint.PrettyPrinter(indent=4)
pref_region = 'us-east-1'
pref_az = 'us-east-1d'
target_instance = ''
target_volume = ''
target_snapshot = ''
forensic_volume = ''
key_name = ''
forensic_instance = ''
forensic_ip = ''

def int_boto(aws_access_key_id,aws_secret_access_key):
    ec2 = boto3.resource('ec2',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,region_name=pref_region)
##Instances
def list_instances():
    print('\nRunning Instances\n')
    for instance in ec2.instances.all():
        if(instance.state['Name']=='running'):
            print("Id: {0}\nPlatform: {1}\nType: {2}\nPublic IPv4: {3}\nAMI: {4}\nState: {5}\n ".format(instance.id, instance.platform, instance.instance_type, instance.public_ip_address, instance.image.id, instance.state['Name']))
##volumes
#ec2 = boto3.resource('ec2', region_name='us-west-2')
def list_volumes(target_instance):
    volumes = ec2.volumes.all() # If you want to list out all volumes
    volumes = ec2.volumes.filter(Filters=[{'Name': 'status', 'Values': ['in-use']}]) # if you want to list out only attached volumes
    target_volume = ''
    for volume in volumes:
        print("Volume ID: {0}\n Attached to Instance: {1}\n Status: {2}\n".format(volume.id, volume.attachments[0]['InstanceId'], volume.attachments[0]['State']))
        if(target_instance==volume.attachments[0]['InstanceId']):
            print(volume.id)
            target_volume = volume.id
#    target_volume = input("Please enter target volume ID... ")
    print("\nTarget Volume selected - {0}".format(target_volume));
    return(target_volume)

##Snapshot
def create_snapshot(target_volume):
    print("Creating Snapshot of Volume {0}".format(target_volume))
    voldesc = "forensic-image-" + target_volume
    snapshot = ec2.create_snapshot(VolumeId=target_volume, Description=voldesc)
    snap = ec2.Snapshot(snapshot.id)
    print('Please wait...\n')
    while(snap.state=='pending'):
        sys.stdout.write('+')
        sys.stdout.flush()
        time.sleep(2)
        snap = ec2.Snapshot(snapshot.id)
    target_snapshot = snapshot.id
    print("\nSnapshot created {0}".format(target_snapshot))
    return(target_snapshot)

#Create new forensic volume
def create_volume(target_snapshot):
    print("\nCreating New Volume with Snapshot Id: {0}".format(target_snapshot))
    volume = ec2.create_volume(SnapshotId=target_snapshot, AvailabilityZone=pref_az)
    vol = ec2.Volume(volume.id)
    while(vol.state=='creating'):
        sys.stdout.write('+')
        sys.stdout.flush()
        time.sleep(2)
        vol = ec2.Volume(volume.id)
    print("\n Created a new volume and attached the forensic snapshot : {0}".format(volume.id))
    forensic_volume = volume.id
    return(forensic_volume)

#Create new Key Pair
def create_keyp(case_id):
    response = ec2.create_key_pair(KeyName=case_id)
    print("\nKey pair created and stored locally - {0}.pem \n\n {1}".format(response.key_name, response.key_material))
    f = open("./cases/"+case_id +"/"+ case_id + ".pem","w+")
    f.write(response.key_material)
    f.close()
    key_name = response.key_name
    return(key_name)


#Create a forensic instances
def create_inst(key_name):
    sgs = list(ec2.security_groups.all())
    c=0
    for sg in sgs:
        if(sg.group_name=='FDA'):
            c=1
            sec_group = sg
            print("\nSecurity Group exists - {0}".format(sec_group.id))
    if(c!=1):
        print("\nCreating Security Group for ingress traffic...")
        sec_group = ec2.create_security_group(GroupName='FDA', Description='Forensic Data Acquisition')
        sec_group.authorize_ingress(
        CidrIp='0.0.0.0/0',
        IpProtocol='-1',
        FromPort=-1,
        ToPort=22)
        print("\nSecurity Group created : {0}".format(sec_group.id))
    instance = ec2.create_instances(BlockDeviceMappings=[
          {
            'DeviceName': '/dev/xvda',
            'VirtualName': 'root',
              'Ebs': {
                  'DeleteOnTermination': True,
                  'VolumeSize': 40,
                  'VolumeType': 'gp2'
              }
              }
      ],
      ImageId='ami-0c6b1d09930fac512',
      MinCount=1,
      MaxCount=1,
      InstanceType='t2.micro',
      KeyName=key_name,
      UserData='''#!/bin/bash
    sudo wget https://github.com/sans-dfir/sift-cli/releases/download/v1.7.1/sift-cli-linux
    sudo mv sift-cli-linux /usr/local/bin/sift
    sudo chmod +x /usr/local/bin/sift
    sudo yum update
    sudo yum upgrade''',
      SecurityGroupIds=[sec_group.id],
      Placement={
          'AvailabilityZone': pref_az}
      )
    print("\nPlease wait...")
    time.sleep(3)
    ins = ec2.Instance(instance[0].id)
    while(ins.state['Name']=='pending'):
        sys.stdout.write('+')
        sys.stdout.flush()
        time.sleep(2)
        ins = ec2.Instance(instance[0].id)
    print("\n\nForensic Instance created successfully - {0}".format(instance[0].id))
    forensic_instance = instance[0].id
    return(forensic_instance)

def mount_snapshot(forensic_volume,forensic_instance):
    ec2.Instance(forensic_instance).attach_volume(VolumeId=forensic_volume, Device='/dev/sdy')
    vol = ec2.Volume(forensic_volume)
    if(vol.attachments[0]['InstanceId'] == forensic_instance):
        print("\nForensic Volume attached")
#snapshot.delete()
def delete_res(aws_access_key_id,aws_secret_access_key):
    client = boto3.client('ec2',aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,region_name=pref_region)
    print("\nCleaning up...\n")
    response = client.delete_snapshot(SnapshotId = target_snapshot)
    print("Deleting Snapshot...")
    response = client.delete_key_pair(KeyName=key_name)
    print("Deleting KeyPair...")
    response = client.terminate_instances(InstanceIds=[forensic_instance])
    print("Terminating Forensic Instance...")
    time.sleep(20)
    response = client.delete_volume(VolumeId=forensic_volume)
    print("Deleting Volume...")
#####MAIN##############

print("\n***AWS Forensic Data Acquisistion***")

if(len(sys.argv)<=1):
    print("\nPlease enter AWS credentials\n")
    aws_access_key_id = input("Key -> ")
    aws_secret_access_key = input("Secret -> ")
else:
    aws_access_key_id = sys.argv[1]
    aws_secret_access_key = sys.argv[2]
    if(len(sys.argv)==4):
        target_instance=sys.argv[3]
int_boto(aws_access_key_id,aws_secret_access_key);
ec2 = boto3.resource('ec2',
aws_access_key_id=aws_access_key_id,
aws_secret_access_key=aws_secret_access_key,region_name=pref_region)
#print("\nAvailable Modules\n1> EC2")
#ch = input("\nSelect module -> ")
case_id = input("\nPlease enter case id - ")
config = Path('./cases/'+case_id+"/"+ case_id +'.log')

if(config.is_file()==True):
    print('Case already found. Reopening options ')
    f=open("./cases/" + case_id + "/"+ case_id +".log", "r")
    f1 = f.readlines()
    target_instance,target_volume,target_snapshot,forensic_volume,key_name,forensic_instance,forensic_ip = [x.split('\n')[0] for x in f1]
    print("Loaded data from log:\nTarget Instance - {0}\nTarget Snapshot - {1}\nForensic Instance - {2} - {3}".format(target_instance,target_snapshot,forensic_instance,forensic_ip))
else:
    if not os.path.exists("./cases/"+case_id):
        os.makedirs("./cases/"+case_id)
    path = './cases/' + case_id +'/'+ case_id + '.log'
    f = open(path,"a+")

if(target_instance==''):
    print("\nListing all running instances on the account")
    list_instances();
    target_instance = input("\nPlease enter the instance id to begin extraction - ");
    log = f.write(target_instance + "\n")
    target_ip = ec2.Instance(target_instance).public_ip_address
if(target_volume==''):
    target_volume = list_volumes(target_instance);
    log = f.write(target_volume + "\n")
if(target_snapshot==''):
    target_snapshot = create_snapshot(target_volume);
    log = f.write(target_snapshot + "\n")
#    input("Press Enter to continue...")
if(forensic_volume==''):
    forensic_volume = create_volume(target_snapshot);
    log = f.write(forensic_volume + "\n")
#    input("Press Enter to continue...")
if(key_name==''):
    key_name = create_keyp(case_id);
    log = f.write(key_name + "\n")
if(forensic_instance==''):
    forensic_instance = create_inst(key_name);
    log = f.write(forensic_instance + "\n")
#    input("Press Enter to create mount the volume to instance...")
    mount_snapshot(forensic_volume,forensic_instance);
    print('\nInstance Ready')
##SSH##
if(forensic_ip==''):
    forensic_ip = ec2.Instance(forensic_instance).public_ip_address
    log = f.write(forensic_ip)

key = "./cases/" + case_id + "/" + key_name + ".pem"
sys.stdout.flush()
o = input("\nChoose action\n1> Manual Inspection - SSH into Forensic Instance\n2> Mount a Read-Only working copy and spawn a shell \n3> Make a DD image and transfer to local system\n4> Transfer cloudtrail logs in the account\nx> Exit\ndel> Delete all created resources\n\n>> ")
ssh=ssh_conn(forensic_ip,key)
if(o=='1'):
    ssh_shell(ssh)
elif(o=='2'):
    ssh_pre(ssh)
    ssh_shell(ssh)
elif(o=='3'):
    ssh_download(ssh,case_id)
elif(o=='4'):
    target_ip = ec2.Instance(target_instance).public_ip_address
    init(case_id,aws_access_key_id,aws_secret_access_key,target_ip,pref_region)
elif(o=='del'):
    delete_res(aws_access_key_id,aws_secret_access_key);
elif(o=='x'):
    exit()
