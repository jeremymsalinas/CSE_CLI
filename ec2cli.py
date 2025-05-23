import boto3, requests, base64, time, random, os, click, sys
from pick import pick
from tabulate import tabulate
from botocore.exceptions import ClientError
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from auto_click_auto import enable_click_shell_completion
from auto_click_auto.constants import ShellType


access_key = os.getenv('AWS_ACCESS_KEY_ID')
secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')

try:
    session = boto3.session.Session(aws_access_key_id=access_key,aws_secret_access_key=secret_key)
    ec2 = session.resource('ec2')
    userInstance = session.client('ec2')
except ClientError as e:
    raise e.response['Error']['Message']
    


def update_session(region):
    global ec2, userInstance
    try: 
        ec2 = session.resource('ec2',region_name=region)
    except ClientError as e:
        raise e.response['Error']['Message']
    
    try:
        userInstance = session.client('ec2',region_name=region)
    except ClientError as e:
        raise e.response['Error']['Message']

# user platform selection screen
def get_platform(region):
    ssm = session.client('ssm', region_name=region)
    quickStartAmis = requests.get(f"https://prod.{region}.qs.console.ec2.aws.dev/get_quickstart_list_en.json").json()['amiList']
    additionalAmis = [['{title}'.format(**key),'{imageId64}'.format(**key)] 
                      for key in quickStartAmis if '{platform}'.format(**key) != 'amazon' 
                      and '{platform}'.format(**key) != 'windows' and '{platform}'.format(**key) != 'x86_64_mac' and 'imageId64' in key.keys()]
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
    try:
        secGroups = ec2.security_groups.all()
    except ClientError as e:
        raise ValueError(e)
    secGroupNames = [group.group_name for group in secGroups]
    secGroupExists = groupName in secGroupNames
    return secGroupExists


# create security group
def create_sec_group(name):
    secGroupName = f'ec2cli-{name}-security-group'
    validName = check_sec_group(secGroupName)
    if not validName:
        try:
            instanceSecGroup = ec2.create_security_group(
                Description='Created from ec2 cli',
                GroupName=secGroupName
            ).id
        except ClientError as e:
            return e.response['Error']['Message']
        return instanceSecGroup
    print("You've entered an existing security group name.")
    exit()

# delete security group
def delete_sec_group(secGroupId):
    try:
        ec2.SecurityGroup(secGroupId).delete()
        return f'{secGroupId} deleted'
    except ClientError:
        return f'Unable to delete {secGroupId}'

# add security group rules
def add_sec_rules(platform,instanceSecGroup):
    cidr = userInstance.describe_vpcs(Filters=[{'Name': 'is-default', 'Values': ['true']}])['Vpcs'][0]['CidrBlock']
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
            raise SystemExit(e)
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
    try:
        userInstance.authorize_security_group_ingress(
            GroupId=instanceSecGroup,
            CidrIp=cidr,
            IpProtocol='-1'
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

# Add autocomplete
@click.command()
def shell_completion():
    """Activate shell completion for this program."""
    enable_click_shell_completion(
        program_name="ec2cli",
        shells={ShellType.BASH, ShellType.FISH, ShellType.ZSH},
        verbose=True,
    )


#  create instance returns instance object
@ec2cli.command('create_instance')
@click.option('--ami', default='', help='ami id')
@click.option('--keypairname', '-kp', default='', help='key pair name')
@click.option('--instancesecgroup', default='', help='security group id')
@click.option('--name', '-n', default='', help='instance name')
@click.option('--region', '-r', default='', help='region')
@click.option('--userdata', default='', type=click.Choice([f for f in os.listdir() if os.path.isfile(f)] + ['']),help='path to user data script')
@click.option('--instancetype',default='t2.medium',help='instance type')
@click.option('--count','-c',default=1,help='number of instances')
@click.option('--volumesize', '-v', default=50, help='volume size')
def create_instance(ami, keypairname, instancesecgroup, name, region, userdata,instancetype,count,volumesize):
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
    else: platform = ''
    if not keypairname:
        keypairname = f'ec2cli-{name}-KP'
        keyPair = create_key_pair(keypairname)
    if not instancesecgroup: 
        instancesecgroup = create_sec_group(name)
        add_sec_rules(platform, instancesecgroup)
    if userdata:
        with open(userdata, 'r') as f:
            userdata = f.read()
    deviceName = list(ec2.images.filter(ImageIds=[ami]))[0].root_device_name
    click.secho(f'Creating {name} Count: {count}',fg='cyan')
    try:
        instances = ec2.create_instances(
            BlockDeviceMappings = [
                {
                    'DeviceName': deviceName,
                    'Ebs': {
                        'DeleteOnTermination': True,
                        'VolumeSize': volumesize,
                        'VolumeType': 'gp3'
                    },
                }
            ],
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
            MaxCount=count,MinCount=1)[0]
    except ClientError as e:
        raise SystemExit(e.response['Error']['Message'])
    
    ids = []
    status = instances.state['Name']
    while status != 'running':
        animate_waiting(10)
        instances.reload()
        status = instances.state['Name']
        

    for instance in ec2.instances.filter(Filters=[{'Name':'tag:Name','Values':[name]}]):
        
        
        ids.append(instance.id)
        click.secho("\n\tInstance created!\n",fg='cyan')
        instanceInfo = userInstance.describe_instances(InstanceIds=[instance.id])['Reservations'][0]['Instances'][0]
        windowsPass = ''
        
        if 'Windows' in platform:
            # wait for password to be generated
            while not windowsPass:
                windowsPass = userInstance.get_password_data(InstanceId=instance.id)['PasswordData']
                animate_waiting(10,"Waiting for password to be generated...")
            with open (keyPair,'r') as f:
                key_text = f.read()
            windowsDecryptedPass = decrypt(key_text,windowsPass)
            print("\r\tDone! 🍻                               \n")
            click.echo(f"\t{click.style('Name:',fg='green')} {name}")
            click.echo(f"\t{click.style('ID:',fg='green')} {instance.id}")
            click.echo(f"\t{click.style('Public DNS:',fg='green')} {instanceInfo['PublicDnsName']}")
            click.echo(f"\t{click.style('Public IP:',fg='green')} {instanceInfo['PublicIpAddress']}")
            click.echo(f"\t{click.style('RDP Password:',fg='green')} {windowsDecryptedPass}\n")
            
        
        else:
            if 'Ubuntu' in platform: user = 'ubuntu'
            
            else: user = 'ec2-user'

            click.echo(f"\t{click.style("Name:",fg='green')} {name}")
            click.echo(f"\t{click.style("ID:",fg='green')} {instance.id}")
            click.echo(f"\t{click.style('Public DNS:',fg='green')} {instanceInfo['PublicDnsName']}")
            click.echo(f"\t{click.style('Public IP:',fg='green')} {instanceInfo['PublicIpAddress']}\n")
            
            print(f"To connect run the following commands:\n chmod 400 {keyPair}\nssh -i {keyPair} {user}@{instanceInfo['PublicIpAddress']}\n")
        
        click.secho("To delete the instance run the following command:",fg='yellow')
        print(f"ec2cli delete_instances {instance.id} -r {region}\n")

    if len(ids) > 1:    
        click.secho("To delete all instances run the following command:",fg='yellow')
        print(f"ec2cli delete_instances {" ".join(ids)} -r {region}\n")
    
    return instances

def animate_waiting(duration, message="Waiting for instance to start..."):
    frames = ["🙂", "🙃", "🙂", "🙃", "😗", "🙄", "😑", "😡", "😤", "🫠"]
    i = 0
    j = 0
    while i < duration:
        click.secho(f"\r\t{message} {frames[j % len(frames)]}\r",nl=False)
        i += 1
        j += 1
        time.sleep(1)


@ec2cli.command('get_instances')
@click.option('--region', default='', help='region')
def get_instances(region):
    if region:
        try:
            update_session(region)
        except ClientError as e:
            raise SystemExit(e)
    tags = []
    platform,id,status,ip,keyName = '','','','',''
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
    ec2List = []
    for instance in ec2cliCreatedInstances:
        for ec2 in instance['Instances']:
            tags = [*ec2['Tags']]
            instanceName = [tag['Value'] for tag in tags if tag['Key'] == 'Name']
            platform = ec2['PlatformDetails']
            id = ec2['InstanceId']
            status = ec2['State']['Name']
            if status == 'running':
                ip = ec2['PublicIpAddress']
            else:
                ip = ''
            keyName = ec2['KeyName']
            ec2List+=[[*instanceName,platform,id,status,ip,keyName]]
    print(tabulate(ec2List, headers=['Name','Platform','ID','Status','IP','KeyName']))


# use ec2 resource to filter ec2cli created instances
def get_instance_ids():
    update_session(session.region_name)
    instances = ec2.instances.filter(Filters=[{'Name':'tag:ec2cli','Values':['true']}])
    instance_ids = [instance.id for instance in instances]
    return instance_ids


# use ec2 resource to filter ec2cli created instances
@ec2cli.command('delete_instances')
@click.argument('instanceids', type=click.Choice(get_instance_ids()),nargs=-1)
@click.option('--region', '-r', default='', help='region')
def delete_instances(instanceids,region):
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    
    if instanceids:
        for id in instanceids:
            instance = ec2.Instance(id)
            name = get_instance_name(instance)
            click.secho(f'Deleting {name}...',fg='red')
            instance.terminate()
        
        for id in instanceids:
            instance = ec2.Instance(id)
            name = get_instance_name(instance)
            instanceSecGroup = get_instance_sec_group(instance)
            instance.wait_until_terminated()
            click.secho(f'{name} deleted!',fg='green')
            
            if instanceSecGroup:
                click.secho(delete_sec_group(instanceSecGroup))

def get_instance_sec_group(instance):
    try:
        secGroups = instance.security_groups
        if len(secGroups) < 1:
            return ""
        else:
            return secGroups[0]['GroupId']
    except ClientError:
        raise SystemExit()

def get_instance_name(instance):
    try:
        tags = instance.tags
    except ClientError:
            raise SystemExit(f"Instance {id} not found in region {session.region_name}.")
    for value in tags:
        if value['Key'] == 'Name':
                name = value['Value']
    return name

@ec2cli.command('start_instance')
@click.argument('instanceids', type=click.Choice(get_instance_ids()), nargs=-1)
@click.option('--region', '-r', default='', help='region')
def start_instance(instanceids, region):
    dir = os.path.expanduser(f'~/ec2cli')
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    for instanceid in instanceids:
        instance = ec2.Instance(instanceid)
        instance.start()
        instance.wait_until_running()
        click.secho(f'Instance {instanceid} started')
        try:
            keyPair = f'{dir}/{instance.key_name}.pem'
            with open(keyPair, 'r') as f:
                key_text = f.read()
        except FileNotFoundError:
            keyPair = ""
        if instance.platform == 'windows' and keyPair:
            password = instance.password_data()['PasswordData']
            decryptedPass = decrypt(key_text, password)
            click.secho(f'PublicIP: {instance.public_ip_address}\nPassword: {decryptedPass}')
        else:
            click.secho(f'To connect run the following commands:\nssh -i {keyPair} ec2-user@{instance.public_ip_address}')


@ec2cli.command('stop_instance')
@click.argument('instanceids', type=click.Choice(get_instance_ids()), nargs=-1)
@click.option('--region', '-r', default='', help='region')
def stop_instance(instanceids, region):
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    for instanceid in instanceids:
        instance = ec2.Instance(instanceid)
        instance.stop()
        instance.wait_until_stopped()
        click.secho(f'Instance {instanceid} stopped')


@ec2cli.command('start_all')
@click.option('--region', '-r', default='', help='region')
def start_all(region):
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    try:
        instance_iterator = ec2.instances.filter(Filters=[{'Name':'tag:ec2cli','Values':['true']}])
        instance_iterator.start()
        click.secho(f'Starting {len(list(instance_iterator))} instances...\n')
        time.sleep(10)
        get_instances(region)
    except ClientError as e:
        raise SystemExit(f"{e.response['Error']['Message']}")


@ec2cli.command('stop_all')
@click.option('--region', '-r', default='', help='region')
def stop_all(region):
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    try:
        instance_iterator = ec2.instances.filter(Filters=[{'Name':'tag:ec2cli','Values':['true']}])
        instance_iterator.stop()
        click.secho(f'Stopping {len(list(instance_iterator))} instances...\n')
        time.sleep(10)
        get_instances(region)
    except ClientError as e:
        raise SystemExit(f"{e.response['Error']['Message']}")


@ec2cli.command('get_password')
@click.argument('instanceids',type=click.Choice(get_instance_ids()),nargs=-1)
@click.option('--region', '-r', default='', help='region')
def get_password(instanceids, region):
    dir = os.path.expanduser(f'~/ec2cli')
    if region:
        try:
            update_session(region)
        except ClientError:
            raise SystemExit("Invalid region id.")
    for instanceid in instanceids:
        instance = ec2.Instance(instanceid)
        try:
            keyPair = f'{dir}/{instance.key_name}.pem'
            with open(keyPair, 'r') as f:
                key_text = f.read()
        except FileNotFoundError:
            keyPair = ""
        if instance.platform == 'windows' and keyPair:
            password = instance.password_data()['PasswordData']
            decryptedPass = decrypt(key_text, password)
            click.secho(f'{instanceid}\nPublicIP: {instance.public_ip_address}\nPassword: {decryptedPass}\n')
        else:
            click.secho(f'To connect run the following commands:\nssh -i {keyPair} ec2-user@{instance.public_ip_address}')