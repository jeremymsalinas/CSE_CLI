import boto3, requests, json
from botocore.exceptions import ClientError

ec2 = boto3.resource('ec2', region_name='us-west-2')
userInstance = boto3.client('ec2')
ssm = boto3.client('ssm')
publicIp = requests.get('https://api.ipify.org?format=json').json()['ip']
ami = ''
# get user platform
# TODO: display a list of windows/linux OS and have user select before loading ami
def get_platform():
    userInput = input('Windows or Linux? ').lower()
    platform = userInput if userInput == 'windows' or userInput == 'linux' else ''
    return platform or 'linux'

platform = get_platform()

# get latest recommended ami
if platform.lower() == 'linux':
    ami = ssm.get_parameter(Name='/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2')['Parameter']['Value']
else:
    ami = ssm.get_parameter(Name='/aws/service/ami-windows-latest/Windows_Server-2016-English-Full-Base')['Parameter']['Value']

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

# delete instance
def delete_instance(instanceId):
    userInstance.terminate_instances(
        InstanceIds=[
            instanceId
        ]
    )
    return f'{instanceId} deleted'

instanceSecGroup = create_sec_group()
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

# enable ssh/rdp depending on platform
instanceInfo = userInstance.describe_instances(InstanceIds=[instance.id])['Reservations'][0]['Instances'][0]

userInstance.authorize_security_group_ingress(
    GroupId=instanceSecGroup,
    CidrIp=f'{publicIp}/32',
    FromPort=22,
    IpProtocol='tcp',
    ToPort=22
)

# enable ssh/rdp depending on platform
print(f"ID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}")
