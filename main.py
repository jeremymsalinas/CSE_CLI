import boto3, requests, base64, time
from pick import pick
from botocore.exceptions import ClientError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

ec2 = boto3.resource('ec2', region_name='us-west-2')
userInstance = boto3.client('ec2')
ssm = boto3.client('ssm')
publicIp = requests.get('https://api.ipify.org?format=json').json()['ip']
keyPair = '/Users/jeremysalinas/Downloads/JeremyS-USWest2-KP.pem'

with open(keyPair, 'r') as key_file:
    key_text = key_file.read()
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
    secGroupName = input('Enter name for new security group: ')
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
    return f'{instanceId} deleted'

# decrypt instance password
def decrypt(key_text, password_data):
    key = RSA.importKey(key_text)
    cipher = PKCS1_v1_5.new(key)
    return cipher.decrypt(base64.b64decode(password_data), None).decode('utf8')

instanceSecGroup = create_sec_group()
add_sec_rules()
# create keypair and save

#  create instance returns instance object
instance = ec2.create_instances(
    ImageId=ami,
    InstanceType='t2.medium',
    KeyName='JeremyS-USWest2-KP',
    SecurityGroupIds=[instanceSecGroup],
    InstanceInitiatedShutdownBehavior='terminate',
    MaxCount=1,MinCount=1)[0]
instance.wait_until_running()

instanceInfo = userInstance.describe_instances(InstanceIds=[instance.id])['Reservations'][0]['Instances'][0]
windowsPass = ''
if 'Windows' in platform:
    # wait for password to be generated
    while not windowsPass:
        windowsPass = userInstance.get_password_data(InstanceId=instance.id)['PasswordData']
        time.sleep(60)
    windowsDecryptedPass = decrypt(key_text,windowsPass)

print(f"ID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}\nRDP Password: {windowsDecryptedPass}")
