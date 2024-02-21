import boto3, requests, base64, time, random, os
from pick import pick
from tabulate import tabulate
from botocore.exceptions import ClientError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

session = boto3.session.Session()
ec2 = session.resource('ec2')
userInstance = session.client('ec2')

# get user platform
# TODO: display a list of windows/linux OS and have user select before loading ami
def get_platform():
    ssm = boto3.client('ssm')
    region = session.region_name
    quickStartAmis = requests.get("https://prod.us-west-2.qs.console.ec2.aws.dev/get_quickstart_list_en.json").json()['amiList']
    additionalAmis = [['{title}'.format(**key),'{imageId64}'.format(**key)] 
                      for key in quickStartAmis if '{platform}'.format(**key) != 'amazon' 
                      and '{platform}'.format(**key) != 'windows' and '{platform}'.format(**key) != 'x86_64_mac']
    os = ''
    amzn2 = '/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
    availablePlatforms = ['Windows Server 2016','Windows Server 2019','Windows Server 2022','Amazon Linux']
    availablePlatforms.extend([x[0] for x in additionalAmis])
    title = 'Please select ec2 platform: '
    platform = pick(availablePlatforms,title,indicator='=>')[0]
    if 'Windows' in platform:
        platformList = platform.split()
        os = f'{platformList[0]}_{platformList[1]}-{platformList[2]}'
        windows = f'/aws/service/ami-windows-latest/{os}-English-Full-Base'
        ami = ssm.get_parameter(Name=windows)['Parameter']['Value']
    elif 'Amazon' in platform:
        ami = ssm.get_parameter(Name=amzn2)['Parameter']['Value']
    else:
        ami = [x[1] for x in additionalAmis if x[0] == platform][0]
    return ami,platform


# check for duplicate group name
def check_sec_group(groupName):
    # userInstance.describe_vpcs(Filters=[{'Name': 'is-default','Values': ['true']}])['Vpcs'][0]['VpcId']
    secGroups = userInstance.describe_security_groups()['SecurityGroups']
    secGroupNames = [group['GroupName'] for group in secGroups]
    secGroupExists = groupName in secGroupNames
    return secGroupExists


# create security group
def create_sec_group(name):
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
def add_sec_rules(platform,instanceSecGroup):
    publicIp = requests.get('https://api.ipify.org?format=json').json()['ip']
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
    if instanceId:
        instance = ec2.Instance(instanceId)
        for value in instance.tags:
            if value['Key'] == 'Name':
                name = value['Value']
        instanceSecGroup = instance.security_groups[0]['GroupId']
    print(f'Deleting {name}')
    instance.terminate()
    instance.wait_until_terminated()
    print(f'{name} deleted')
    print(delete_sec_group(instanceSecGroup))
    

# decrypt instance password
def decrypt(key_text, password_data):
    key = RSA.importKey(key_text)
    cipher = PKCS1_v1_5.new(key)
    return cipher.decrypt(base64.b64decode(password_data), None).decode('utf8')


# create keypair and save
def create_key_pair(keyPairName):
    dir = os.path.expanduser(f'~/ec2cli')
    if not os.path.exists(dir):
        os.mkdir(dir)
    path = f'{dir}/{keyPairName}.pem'
    keyPair = userInstance.create_key_pair(KeyName=keyPairName)
    with open(path,'w+') as f:
        f.write(keyPair['KeyMaterial'])
    return path


#  create instance returns instance object
def create_instance(ami='', keyPairName='', instanceSecGroup='',name=''):
    randAdj = ['unique','glowing','beautiful','magnificient','ornery','pleasant','grouchy']
    randNoun = ['pheasant','parrot','cockatoo','curassow','chicken','penguin','pidgeon']
    if not name: name = f'{random.choice(randAdj)}-{random.choice(randNoun)}-{int(time.time())}'
    if not ami: ami,platform = get_platform()
    if not keyPairName:
        keyPairName = f'ec2cli-{name}-KP'
        keyPair = create_key_pair(keyPairName)
    if not instanceSecGroup: 
        instanceSecGroup = create_sec_group(name)
        add_sec_rules(platform, instanceSecGroup)
    print(f'Creating {name}')
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
    instanceInfo = userInstance.describe_instances(InstanceIds=[instance.id])['Reservations'][0]['Instances'][0]
    windowsPass = ''
    if 'Windows' in platform:
        # wait for password to be generated
        while not windowsPass:
            print("Waiting for password to be generated...")
            windowsPass = userInstance.get_password_data(InstanceId=instance.id)['PasswordData']
            time.sleep(30)
        with open (keyPair,'r') as f:
            key_text = f.read()
        windowsDecryptedPass = decrypt(key_text,windowsPass)
        print(f"Name: {name}\nID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}\nRDP Password: {windowsDecryptedPass}")
    else:
        if 'Ubuntu' in platform: user = 'ubuntu'
        else: user = 'ec2-user'
        print(f"Name: {name}\nID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}")
        print(f"To connect run the following commands:\nchmod 400 {keyPair}\nssh -i {keyPair} {user}@{instanceInfo['PublicIpAddress']}")
    return instance

def get_ec2_cli_instances():
    tags = []
    ec2cliCreatedInstances = [instance for instance in userInstance.describe_instances(Filters=[
        {
            'Name': 'tag:ec2cli',
            'Values': [
                'true'
                ]
        }
    ])['Reservations']]
    for instance in ec2cliCreatedInstances:
        tags += [*instance['Instances'][0]['Tags']]
    instanceNames = [[tag['Value']] for tag in tags if tag['Key'] == 'Name']
    for count,name in enumerate(instanceNames):
        name.extend([ec2cliCreatedInstances[count]['Instances'][0]['InstanceId'],ec2cliCreatedInstances[count]['Instances'][0]['State']['Name']])
    print(tabulate(instanceNames, headers=['Name','ID','State']))

    