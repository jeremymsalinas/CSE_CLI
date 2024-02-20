import boto3, requests, base64, time, random, os
from pick import pick
from botocore.exceptions import ClientError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

randAdj = ['unique','glowing','beautiful','magnificient','ornery','pleasant','grouchy']
randNoun = ['pheasant','parrot','cockatoo','curassow','chicken','penguin','pidgeon']
name = f'{random.choice(randAdj)}-{random.choice(randNoun)}-{int(time.time())}'
ec2 = boto3.resource('ec2', region_name='us-west-2')
userInstance = boto3.client('ec2')
ssm = boto3.client('ssm')
publicIp = requests.get('https://api.ipify.org?format=json').json()['ip']
keyPairName = f'ec2cli-{name}-KP'

# get user platform
# TODO: display a list of windows/linux OS and have user select before loading ami
def get_platform():
    os = ''
    amzn2 = '/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
    availablePlatforms = ['Windows Server 2016','Windows Server 2019','Windows Server 2022','Amazon Linux']
    title = 'Please select ec2 platform: '
    platform = pick(availablePlatforms,title,indicator='=>')[0].split()
    if 'Windows' in platform:
        os = f'{platform[0]}_{platform[1]}-{platform[2]}'
        windows = f'/aws/service/ami-windows-latest/{os}-English-Full-Base'
        return windows
    return amzn2

platform = get_platform()

# get latest recommended ami
ami = ssm.get_parameter(Name=platform)['Parameter']['Value']

# check for duplicate group name
def check_sec_group(groupName):
    # userInstance.describe_vpcs(Filters=[{'Name': 'is-default','Values': ['true']}])['Vpcs'][0]['VpcId']
    secGroups = userInstance.describe_security_groups()['SecurityGroups']
    secGroupNames = [group['GroupName'] for group in secGroups]
    secGroupExists = groupName in secGroupNames
    return secGroupExists


# create security group
def create_sec_group():
    secGroupName = f'ec2cli-{name}-security-group'
    validName = check_sec_group(secGroupName)
    if not validName:
        instanceSecGroup = userInstance.create_security_group(
            Description='Created from ec2 cli',
            GroupName=secGroupName
        )['GroupId']
        return instanceSecGroup
    print("You've entered an existing security group name.")
    exit

# delete security group
def delete_sec_group(secGroupId):
    userInstance.delete_security_group(
        GroupId=secGroupId
    )
    return f'{secGroupId} deleted'

# add security group rules
def add_sec_rules():
    if 'Windows' in platform:
        userInstance.authorize_security_group_ingress(
            GroupId=instanceSecGroup,
            CidrIp=f'{publicIp}/32',
            FromPort=3389,
            IpProtocol='tcp',
            ToPort=3389
        )
    else: 
        userInstance.authorize_security_group_ingress(
        GroupId=instanceSecGroup,
        CidrIp=f'{publicIp}/32',
        FromPort=22,
        IpProtocol='tcp',
        ToPort=22
    )

# delete instance
def delete_instance(instanceId):
    userInstance.terminate_instances(
        InstanceIds=[
            instanceId
        ]
    )
    print(f'Deleting {name}')
    userInstance.get_waiter('instance_terminated').wait(InstanceIds=[instanceId])
    print(f'{name} deleted')
    print(delete_sec_group(instanceSecGroup))
    

# decrypt instance password
def decrypt(key_text, password_data):
    key = RSA.importKey(key_text)
    cipher = PKCS1_v1_5.new(key)
    return cipher.decrypt(base64.b64decode(password_data), None).decode('utf8')

instanceSecGroup = create_sec_group()
add_sec_rules()
# create keypair and save
def create_key_pair():
    dir = os.path.expanduser(f'~/ec2cli')
    if not os.path.exists(dir):
        os.mkdir(dir)
    path = f'{dir}/ec2cli-{name}-KP.pem'
    keyPair = userInstance.create_key_pair(KeyName=keyPairName)
    with open(path,'w+') as f:
        f.write(keyPair['KeyMaterial'])
    return path

keyPair = create_key_pair() # TODO: remove hard link, create keypair and store for connections
#  create instance returns instance object
instance = ec2.create_instances(
    ImageId=ami,
    InstanceType='t2.medium',
    KeyName=keyPairName,
    SecurityGroupIds=[instanceSecGroup],
    InstanceInitiatedShutdownBehavior='terminate',
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': f'{name}'
                },
                {
                    'Key': 'ec2cli',
                    'Value': 'true'
                }
            ]
        }
    ],
    MaxCount=1,MinCount=1)[0]
print("Waiting for instance to become available...")
instance.wait_until_running()
print("Instance online!\n")

def get_ec2_cli_instances():
    ec2cliCreatedInstance = userInstance.describe_instances(Filters=[
        {
            'Name': 'tag:ec2cli',
            'Values': [
                'true'
                ]
        }
    ])['Reservations'][0]['Tags']
    print(ec2cliCreatedInstance)

instanceInfo = userInstance.describe_instances(InstanceIds=[instance.id])['Reservations'][0]['Instances'][0]
windowsPass = ''
if 'Windows' in platform:
    # wait for password to be generated
    while not windowsPass:
        windowsPass = userInstance.get_password_data(InstanceId=instance.id)['PasswordData']
        time.sleep(30)
    with open (keyPair,'r') as f:
        key_text = f.readlines()
    windowsDecryptedPass = decrypt(key_text,windowsPass)
    print(f"Name: {name}\nID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}\nRDP Password: {windowsDecryptedPass}")
else:
    print(f"Name: {name}\nID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}")
    print(f"To connect run the following commands:\nchmod 400 {keyPair}\nssh -i {keyPair} ec2-user@{instanceInfo['PublicIpAddress']}")

