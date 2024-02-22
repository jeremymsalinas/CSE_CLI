import boto3, requests, base64, time, random, os, click
from pick import pick
from tabulate import tabulate
from botocore.exceptions import ClientError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

access_key = os.getenv('AWS_ACCESS_KEY_ID')
secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
session = boto3.session.Session(aws_access_key_id=access_key,aws_secret_access_key=secret_key)
ec2 = session.resource('ec2')
userInstance = session.client('ec2')

def update_session(region):
    global ec2, userInstance
    ec2 = session.resource('ec2',region_name=region)
    userInstance = session.client('ec2',region_name=region)

# get user platform
# TODO: display a list of windows/linux OS and have user select before loading ami
def get_platform(region):
    ssm = session.client('ssm', region_name=region)
    quickStartAmis = requests.get(f"https://prod.{region}.qs.console.ec2.aws.dev/get_quickstart_list_en.json").json()['amiList']
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
    try:
        secGroups = userInstance.describe_security_groups()['SecurityGroups']
    except ClientError as e:
        raise ValueError(e)
    secGroupNames = [group['GroupName'] for group in secGroups]
    secGroupExists = groupName in secGroupNames
    return secGroupExists


# create security group
def create_sec_group(name):
    secGroupName = f'ec2cli-{name}-security-group'
    validName = check_sec_group(secGroupName)
    if not validName:
        try:
            instanceSecGroup = userInstance.create_security_group(
            Description='Created from ec2 cli',
            GroupName=secGroupName
        )['GroupId']
        except ClientError as e:
            return e.response['Error']['Message']
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
    try:
        publicIp = requests.get('https://api.ipify.org?format=json').json()['ip']
    except requests.exceptions.RequestException as e:
        raise SystemExit(e)
    if 'Windows' in platform:
        try:
            userInstance.authorize_security_group_ingress(
                GroupId=instanceSecGroup,
                CidrIp=f'{publicIp}/32',
                FromPort=3389,
                IpProtocol='tcp',
                ToPort=3389
            )
        except ClientError as e:
            print(f'{e.response["Error"]["Message"]}')
            exit()
    else:
        try:
            userInstance.authorize_security_group_ingress(
                GroupId=instanceSecGroup,
                CidrIp=f'{publicIp}/32',
                FromPort=22,
                IpProtocol='tcp',
                ToPort=22
            )
        except ClientError as e:
            raise SystemExit(e)


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
    try:
        keyPair = userInstance.create_key_pair(KeyName=keyPairName)
    except ClientError as e:
        raise SystemExit(e)
    with open(path,'w+') as f:
        f.write(keyPair['KeyMaterial'])
    return path

@click.group(invoke_without_command=True)
def ec2cli():
    pass

#  create instance returns instance object
@ec2cli.command('create_instance')
@click.option('--ami', default='', help='ami id')
@click.option('--keypairname', '-kp', default='', help='key pair name')
@click.option('--instancesecgroup', default='', help='security group id')
@click.option('--name', '-n', default='', help='instance name')
@click.option('--region', '-r', default='', help='region')
@click.option('--userdata', default='', help='path to user data script')
@click.option('--instancetype',default='t2.medium',help='instance type')
def create_instance(ami, keypairname, instancesecgroup, name, region, userdata,instancetype):
    randAdj = ['unique','glowing','beautiful','magnificient','ornery','pleasant','grouchy']
    randNoun = ['pheasant','parrot','cockatoo','curassow','chicken','penguin','pidgeon']
    if not name: name = f'{random.choice(randAdj)}-{random.choice(randNoun)}-{int(time.time())}'
    if region: 
        try:
            update_session(region)
        except ClientError as e:
            raise SystemExit(e)
    else:
        region = session.region_name
    if not ami: ami,platform = get_platform(region)
    if not keypairname:
        keypairname = f'ec2cli-{name}-KP'
        keyPair = create_key_pair(keypairname)
    if not instancesecgroup: 
        instancesecgroup = create_sec_group(name)
        add_sec_rules(platform, instancesecgroup)
    if userdata:
        with open(userdata, 'r') as f:
            userdata = f.read()
    click.secho(f'Creating {name}',fg='cyan')
    try:
        instance = ec2.create_instances(
            ImageId=ami,
            InstanceType=instancetype,
            KeyName=keypairname,
            SecurityGroupIds=[instancesecgroup],
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
            UserData=userdata,
            MaxCount=1,MinCount=1)[0]
    except ClientError as e:
        raise SystemExit(e.response['Error']['Message'])
    click.secho("Waiting for instance to become available...",fg='cyan',blink=True)
    instance.wait_until_running()
    click.secho("Instance online!",fg='cyan')
    instanceInfo = userInstance.describe_instances(InstanceIds=[instance.id])['Reservations'][0]['Instances'][0]
    windowsPass = ''
    if 'Windows' in platform:
        # wait for password to be generated
        while not windowsPass:
            click.secho("Waiting for password to be generated...",fg='cyan')
            windowsPass = userInstance.get_password_data(InstanceId=instance.id)['PasswordData']
            time.sleep(30)
        with open (keyPair,'r') as f:
            key_text = f.read()
        windowsDecryptedPass = decrypt(key_text,windowsPass)
        print(f"Name: {name}\nID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}\nRDP Password: {windowsDecryptedPass}\n")
    else:
        if 'Ubuntu' in platform: user = 'ubuntu'
        else: user = 'ec2-user'
        print(f"Name: {name}\nID: {instance.id}\nDNS: {instanceInfo['PublicDnsName']}\nPublic IP: {instanceInfo['PublicIpAddress']}\nKeyName: {instanceInfo['KeyName']}\n")
        print(f"To connect run the following commands:\nchmod 400 {keyPair}\nssh -i {keyPair} {user}@{instanceInfo['PublicIpAddress']}\n")
    click.secho("To delete the instance run the following command:",fg='yellow')
    print(f"ec2cli delete_instance -id {instance.id} -r {region}\n")
    return instance

@ec2cli.command('get_instances')
@click.option('--region', default='', help='region')
def get_instances(region):
    if region:
        try:
            update_session(region)
        except ClientError as e:
            raise SystemExit(e)
    tags = []
    try:
        ec2cliCreatedInstances = [instance for instance in userInstance.describe_instances(Filters=[
            {
                'Name': 'tag:ec2cli',
                'Values': [
                    'true'
                    ]
            }
        ])['Reservations']]
    except ClientError as e:
        raise SystemExit(e.response['Error']['Message'])
    for instance in ec2cliCreatedInstances:
        tags += [*instance['Instances'][0]['Tags']]
    instanceNames = [[tag['Value']] for tag in tags if tag['Key'] == 'Name']
    for count,name in enumerate(instanceNames):
        name.extend([ec2cliCreatedInstances[count]['Instances'][0]['InstanceId'],
                     ec2cliCreatedInstances[count]['Instances'][0]['State']['Name']])
    print(tabulate(instanceNames, headers=['Name','ID','State']))

# delete instance
@ec2cli.command('delete_instance')
@click.option('--instanceid', '-id', default='', help='instance id')
@click.option('--region', '-r', default='', help='region')
def delete_instance(instanceid,region):
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    if instanceid:
        instance = ec2.Instance(instanceid)
        try:
            tags = instance.tags
        except ClientError:
            raise SystemExit(f"Instance {instanceid} not found in region {session.region_name}.")
        for value in tags:
            if value['Key'] == 'Name':
                name = value['Value']
        instanceSecGroup = instance.security_groups[0]['GroupId']
    click.secho(f'Deleting {name}...',fg='red')
    instance.terminate()
    instance.wait_until_terminated()
    click.secho(f'{name} deleted',fg='green')
    click.secho(delete_sec_group(instanceSecGroup),fg='green')    