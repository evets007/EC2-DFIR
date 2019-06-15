import paramiko
import re
import interactive
#from scp import SCPClient
import time


def ssh_conn(ip,key_name):
    try:
        ssh = paramiko.SSHClient()
        k = paramiko.RSAKey.from_private_key_file(key_name)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname = ip, username = "ec2-user", pkey = k, port=22, compress=True)
        print("Connected to Forensic Instance")
    except paramiko.AuthenticationException:
        print("Connection Failed, Please check the keys file")
    return(ssh)

def ssh_shell(ssh):
    connection = ssh.invoke_shell()
    interactive.interactive_shell(connection)
    connection.close()
    ssh.close()

def ssh_pre(ssh):
    c = ['sudo yum install -y git','sudo yum install -y python','sudo yum install -y python-pip','sudo pip install margaritashotgun','sudo mkdir working_copy','sudo mount -o ro /dev/xvdy1 working_copy']
    for i in c:
        print(i)
        stdin, stdout, stderr = ssh.exec_command(i)
        for line in stdout.read().splitlines():
            print(line)
    print("Mounted successfully")

def ssh_download(ssh,case_id):
    stdin, stdout, stderr = ssh.exec_command('ls '+case_id+'.dd' )
    a = str(stdout.read())
    if(case_id not in a):
        print("Making disk image of the attached drive using DD - Block Size 1024, Please wait...")
        stdin, stdout, stderr = ssh.exec_command('sudo dd if=/dev/xvdy of=/home/ec2-user/'+case_id+'.dd bs=1M')
        stdout.read().splitlines()
        print("Extraction complete. Creating MD5 hash, Please wait...")
        stdin, stdout, stderr = ssh.exec_command('md5sum '+case_id+'.dd > '+case_id+'.md5')
        stdout.read()
        stdin, stdout, stderr = ssh.exec_command('cat '+case_id+'.md5')
        print("MD5 Hash - {0}".format(stdout.read().splitlines()))
    print("Disk Image extraction done. Initiating FTP transfer, Please wait...")
    ftp_client=ssh.open_sftp()
#    ftp_client=SCPClient(ssh.get_transport())
    ftp_client.get("/home/ec2-user/"+case_id+".dd","./cases/"+case_id+"/"+case_id+"_forensic_copy.dd", callback=byte_count)
    ftp_client.get("/home/ec2-user/"+case_id+".md5","./cases/"+case_id+"/"+case_id+"_forensic_copy.md5", callback=byte_count)
#    ftp_client.get("/home/ec2-user/"+case_id+".dd","./cases/"+case_id+"_forensic_copy.dd", preserve_times=True)
    ftp_client.close()
    print("Transfer Complete. Please find the DD file in the case directory.")

def byte_count(xfer, to_be_xfer):
    print(" Transferred: {0:.0f} %".format((xfer / to_be_xfer) * 100),end='\r')

#ssh = ssh_conn("18.234.188.68")
#ssh_pre(ssh)
#ssh_download(ssh)
#ssh_shell(ssh)
