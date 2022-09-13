import os
import sys
import json
import boto3
import urllib3
from datetime import date, datetime
import time
import logging
from ipaddress import IPv4Network

LOGGER = logging.getLogger()
if 'log_level' in os.environ:
    LOGGER.setLevel(os.environ['log_level'])
    print('Log level set to %s' % LOGGER.getEffectiveLevel())
else:
    LOGGER.setLevel(logging.ERROR)

session = boto3.Session()

def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError('Type %s not serializable' % type(obj))

def send_response(event, context, responseStatus, responseData, physicalResourceId=None,noEcho=False):
    responseUrl = event['ResponseURL']
    ls = context.log_stream_name
    responseBody = {}
    responseBody['Status'] = responseStatus
    responseBody['Reason'] = 'View details in Log Stream: '+ls
    responseBody['PhysicalResourceId'] = physicalResourceId or ls
    responseBody['StackId'] = event['StackId']
    responseBody['RequestId'] = event['RequestId']
    responseBody['LogicalResourceId'] = event['LogicalResourceId']
    responseBody['NoEcho'] = noEcho
    responseBody['Data'] = responseData
    jsonResponseBody = json.dumps(responseBody)
    print('ResponseBody: \n'+jsonResponseBody)
    headers = {
        'content-type': '',
        'content-length': str(len(jsonResponseBody))
    }
    http = urllib3.PoolManager()
    try:
        response = http.request('PUT', responseUrl, body=jsonResponseBody, headers=headers)
        print('StatusCode = '+response.reason)
    except Exception as e:
        print(f'send_response(..) failed executing requests.put(..): {e}')

def get_private_scope(ec2_client):
    filters = []
    privateScope = {
            'Name': 'ipam-scope-type',
            'Values': [ 'private' ]
    }
    filters.append(privateScope)
    try:
        paginator = ec2_client.get_paginator('describe_ipam_scopes')
        iterator = paginator.paginate(Filters=filters)
        for page in iterator:
            private_scope_id = page['IpamScopes'][0]['IpamScopeId']
            print('Return Private Scope Id: {}'.format(private_scope_id))
            return private_scope_id
    except Exception as e:
        LOGGER.error(f'failed in describe_ipam_scopes(..): {e}')
        LOGGER.error(str(e))

def get_parent_pool(ec2_client, member_region, workload_type):
    filters = []
    localeFilter = {
        'Name': 'locale',
        'Values': [ member_region ]
    }
    depthFilter = {
        'Name': 'pool-depth',
        'Values': [ '3' ]
    }
    filters.append(localeFilter)
    filters.append(depthFilter)
    try:
        paginator = ec2_client.get_paginator('describe_ipam_pools')
        iterator = paginator.paginate(Filters=filters)
        for page in iterator:
            for pool in page['IpamPools']:
                if 'Dev pool' in pool['Description']:
                    parent_pool_id = pool['IpamPoolId']
                    print('Return Parent Pool Id: {}'.format(parent_pool_id))
                    return parent_pool_id
    except Exception as e:
        LOGGER.error(f'failed in list_pools(..): {e}')
        LOGGER.error(str(e))

def create_pool(ec2_client, parent_pool_id, member_account, member_region, scope_id, workload_type, workload_id):
    desc = '{} {} {} pool for {}'.format(member_region, workload_type, workload_id, member_account)
    tagSpecs = []
    tagSpec = {
        'ResourceType': 'ipam-pool',
        'Tags': [
            {
                'Key': 'Name',
                'Value': 'Dev workload'
            },
            {
                'Key': 'Account',
                'Value': member_account
            },
            {
                'Key': 'WorkloadId',
                'Value': workload_id
            }
        ]
    }
    tagSpecs.append(tagSpec)
    try:
        response = ec2_client.create_ipam_pool(IpamScopeId=scope_id,
                Locale=member_region,
                SourceIpamPoolId=parent_pool_id, 
                Description=desc,
                AddressFamily='ipv4',
                AllocationMinNetmaskLength=24,
                AllocationMaxNetmaskLength=28,
                AllocationDefaultNetmaskLength=24,
                TagSpecifications=tagSpecs)
        print('IPAM Pool created with Id: {}'.format(response['IpamPool']['IpamPoolId']))
        return response['IpamPool']['IpamPoolId']
    except Exception as e:
        LOGGER.error(f'failed in create_ipam_pool(..): {e}')
        LOGGER.error(str(e))

def get_parent_pool_cidrs(parent_pool_id):
    parentPoolCidrs = []    
    try:
        ec2_client = session.client('ec2')
        paginator = ec2_client.get_paginator('get_ipam_pool_cidrs')
        iterator = paginator.paginate(IpamPoolId=parent_pool_id)
        for page in iterator:
            for ipamPoolCidr in page['IpamPoolCidrs']:
                if ipamPoolCidr['State'] == 'provisioned':
                    parentPoolCidrs.append(ipamPoolCidr['Cidr'])
        print('Parent Pool CIDRS = ')
        print(parentPoolCidrs)
    except Exception as  e:
        LOGGER.error(f'failed in get_ipam_pool_cidrs(..): {e}')
        LOGGER.error(str(e))
    return parentPoolCidrs

def provision_cidr(region, parent_pool_id, pool_id, netmaskLength):
    availableCidr = ''
    try:
        parentPoolCidrs = get_parent_pool_cidrs(parent_pool_id)
        # expect only 1 parent pool cidr
        parentPoolCidr = parentPoolCidrs[0]
        print('Parent Pool CIDR: {}'.format(parentPoolCidr))
        ec2_client = session.client('ec2', endpoint_url=f"https://ec2.{region}.amazonaws.com", region_name=region)
        allocatedCidrs = get_allocations(ec2_client, parent_pool_id)
        availableCidr = get_new_cidr(parentPoolCidr, allocatedCidrs, netmaskLength)
        ec2_client = session.client('ec2')
        ec2_client.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=availableCidr)
        print('Provisioned Cidr: {} in Pool: {}'.format(availableCidr, pool_id))
    except Exception as e:
        LOGGER.error(f'failed in provision_ipam_pool_cidr(..): {e}')
        LOGGER.error(str(e))
    return availableCidr

def get_allocations(ec2_client, pool_id):
    allocated_cidrs = []
    try:
        response = ec2_client.get_ipam_pool_allocations(IpamPoolId=pool_id)
        for  allocation in response['IpamPoolAllocations']:
            allocated_cidrs.append(allocation['Cidr'])
        print('Allocated CIDRs = ')
        print(allocated_cidrs)
    except Exception as e:
        LOGGER.error(f'failed in gget_ipam_pool_allocations(..): {e}')
        LOGGER.error(str(e))
    return allocated_cidrs

def get_new_cidr(parentPoolCidr, allocatedCidrs, netmaskLength):
    availableCidr = ''
    all_subnets = list(IPv4Network(parentPoolCidr).subnets(new_prefix=netmaskLength))
    if len(allocatedCidrs) > 0:
        # exclude allocated cidrs
        for allocatedCidr in allocatedCidrs:
            all_subnets.remove(IPv4Network(allocatedCidr))
    availableCidr = str(all_subnets[0])
    print('Available CIDR: {}'.format(availableCidr))
    return availableCidr

def get_pool_state(region, pool_id):
    filters = []
    poolIdFilter = {
        'Name': 'ipam-pool-id',
        'Values': [ pool_id ]
    }
    filters.append(poolIdFilter)
    try:
        ec2_client = session.client('ec2', endpoint_url=f"https://ec2.{region}.amazonaws.com", region_name=region)
        response = ec2_client.describe_ipam_pools(Filters=filters)
        if 'IpamPools' in response and len(response['IpamPools']) > 0:
            pool_state = response['IpamPools'][0]['State']
            print('Return Pool State: {}'.format(pool_state))
            return pool_state
    except Exception as e:
        LOGGER.error(f'failed in describe_ipam_pools(..): {e}')
        LOGGER.error(str(e))

def get_pool_cidr_state(pool_id, cidr):
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.get_ipam_pool_cidrs(IpamPoolId=pool_id)
        for poolCidr in response['IpamPoolCidrs']:
            if poolCidr['Cidr'] == cidr:
                cidr_state = poolCidr['State']
                print('Return Cidr State: {}'.format(cidr_state))
                return cidr_state
    except Exception as e:
        LOGGER.error(f'failed in get_ipam_pool_cidrs(..): {e}')
        LOGGER.error(str(e))

def is_pool_created(region, pool_id):
    pool_created = False
    # check pool state
    # wait until state == 'create-complete'
    i = int(1)
    while (i < 60):
        state = get_pool_state(region, pool_id)
        if state == 'create-complete':
            pool_created = True
            break
        i = i + 1
        # wait
        print('wait 10 seconds')
        time.sleep(10)
    return pool_created

def is_cidr_provisioned(pool_id, cidr):
    cidr_provisioned = False
    i = int(1)
    while (i < 60):
        state = get_pool_cidr_state(pool_id, cidr)
        if state == 'provisioned':
            cidr_provisioned = True
            break
        i = i + 1
        # wait
        print('wait 10 seconds')
        time.sleep(10)
    return cidr_provisioned

def allocate_cidr(region, pool_id, netmaskLength):
    try:
        ec2_client = session.client('ec2', endpoint_url=f"https://ec2.{region}.amazonaws.com", region_name=region)
        response = ec2_client.allocate_ipam_pool_cidr(IpamPoolId=pool_id, NetmaskLength=netmaskLength)
        print('Allocated CIDR: {} from IPAM Pool: {}'.format(response['IpamPoolAllocation']['Cidr'], pool_id))
        return response['IpamPoolAllocation']['Cidr']
    except Exception as e:
        LOGGER.error(f'failed in allocate_ipam_pool_cidr(..): {e}')
        LOGGER.error(str(e))

def get_pool_id(event):
    resProps  = event['ResourceProperties']
    member_region = resProps['member_region']
    member_account = resProps['member_account']
    workload_id = resProps['workload_id']
    filters = []
    filter1 = {
        'Name': 'locale',
        'Values': [ member_region ]
    }
    filter2 = {
        'Name': 'tag:Account',
        'Values': [ member_account ]
    }
    filter3 = {
        'Name': 'tag:WorkloadId',
        'Values': [ workload_id ]
    }
    filters.append(filter1)
    filters.append(filter2)
    filters.append(filter3)
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_ipam_pools(Filters=filters)
        if 'IpamPools' in response:
            pool_id = response['IpamPools'][0]['IpamPoolId']
            print('Return IPAM Pool Id: {}'.format(pool_id))
            return pool_id
    except Exception as e:
        LOGGER.error(f'failed in describe_ipam_pools(..): {e}')
        LOGGER.error(str(e))
        raise e

def ignore_cidr(region, pool_id, cidr, private_scope):
    filters = []
    cidrFilter = {
        'Name': 'cidr',
        'Values': [ cidr ]
    }
    filters.append(cidrFilter)
    try:
        ec2_client = session.client('ec2', endpoint_url=f"https://ec2.{region}.amazonaws.com", region_name=region)
        response = ec2_client.get_ipam_pool_allocations(IpamPoolId=pool_id, Filters=filters)
        if 'IpamPoolAllocations' in response:
            # get first item
            ipamPoolAllocation = response['IpamPoolAllocations'][0]
        ec2_client.modify_ipam_resource_cidr(
            ResourceId=ipamPoolAllocation['ResourceId'],
            ResourceCidr=cidr,
            ResourceRegion=ipamPoolAllocation['ResourceRegion'],
            CurrentIpamScopeId=private_scope,
            Monitored=False
        )
    except Exception as e:
        LOGGER.error(f'failed in modify_ipam_resource_cidr(..): {e}')
        LOGGER.error(str(e))
        raise e

def get_resource_cidr(ec2_client, pool_id, private_scope):
    try:
        response = ec2_client.get_ipam_resource_cidrs(IpamScopeId=private_scope, IpamPoolId=pool_id)
        return response
    except Exception as e:
        print(f'failed in get_ipam_resource_cidrs(..): {e}')
        print(str(e))
        raise e

def is_resource_cidr_ignored(ec2_client, pool_id, private_scope):
    cidr_ignored = False
    i = int(1)
    while (i < 60):
        try:
            response = get_resource_cidr(ec2_client, pool_id, private_scope)
            # only 1 resource cidr
            cidr = response['IpamResourceCidrs'][0]
            if cidr['ManagementState'] == 'ignored':
                cidr_ignored = True
                break
            i = i + 1
            # wait
            print('wait 30 seconds')
            time.sleep(30)
        except Exception as e:
            print(f'failed in get_resource_cidr(..): {e}')
            print(str(e))
    return cidr_ignored

def deprovision_cidrs(ec2_client, region, pool_id, private_scope):
    poolCidrs = []
    try:
        response = ec2_client.get_ipam_pool_cidrs(IpamPoolId=pool_id)
        if 'IpamPoolCidrs' in response:
            for ipamPoolCidr in response['IpamPoolCidrs']:
                poolCidrs.append(ipamPoolCidr['Cidr'])
        for poolCidr in poolCidrs:
            ignore_cidr(region, pool_id, poolCidr, private_scope)
            if is_resource_cidr_ignored(ec2_client, pool_id,  private_scope):
                print('Cidr: {} is Unmanaged OR Ignored'.format(poolCidr))
                print('Deprovision Cidr: {} ..'.format(poolCidr))
                try:
                    ec2_client.deprovision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=poolCidr)
                    if is_cidr_deprovisioned(ec2_client, pool_id, poolCidr):
                        print('Cidr: {} deprovisioned in Pool: {}'.format(poolCidr, pool_id))
                except Exception as e:
                    LOGGER.warning(f'failed in deprovision_ipam_pool_cidr(..): {e}')
    except Exception as e:
        LOGGER.error(f'failed in get_ipam_pool_cidrs(..): {e}')
        LOGGER.error(str(e))
        raise e
    return poolCidrs

def is_cidr_deprovisioned(ec2_client, pool_id, cidr):
    is_deprovisioned = False
    i = int(1)
    while (i < 60):
        try:
            response = ec2_client.get_ipam_pool_cidrs(IpamPoolId=pool_id)
            for ipamPoolCidr in response['IpamPoolCidrs']:
                if cidr == ipamPoolCidr['Cidr']:
                    if ipamPoolCidr['State'] == 'deprovisioned':
                        is_deprovisioned = True
                        break
        except Exception as e:
            LOGGER.error(f'failed in get_ipam_pool_cidrs(..): {e}')
            LOGGER.error(str(e))
        if is_deprovisioned:
            break
        i = i + 1
        print('wait 10 seconds')
        time.sleep(10)
    return is_deprovisioned

def delete_pool(ec2_client, pool_id):
    try:
        ec2_client.delete_ipam_pool(IpamPoolId=pool_id)
        print('Pool: {} deleted'.format(pool_id))
        return pool_id
    except Exception as e:
        LOGGER.error(f'failed in delete_ipam_pool(..): {e}')
        LOGGER.error(str(e))
        raise e

def get_pool_arn(pool_id):
    filters = []
    poolIdFilter = {
        'Name': 'ipam-pool-id',
        'Values':  [ pool_id ]
    }
    filters.append(poolIdFilter)
    try:
        ec2_client = session.client('ec2')
        response = ec2_client.describe_ipam_pools(Filters=filters)
        if 'IpamPools' in response:
            pool_arn = response['IpamPools'][0]['IpamPoolArn']
            print('Return Pool Arn: {}'.format(pool_arn))
            return pool_arn
    except Exception as e:
        print(f'failed in describe_ipam_pools(..): {e}')
        print(str(e))
        raise e

def share_pool(event, pool_id):
    try:
        resProps = event['ResourceProperties']
        member_account = resProps['member_account']
        member_region = resProps['member_region']
        workload = resProps['workload_type']
        workload_id = resProps['workload_id']
        share_name = '{}-{}-{}-{}'.format(member_account,member_region,workload,workload_id)
        share_tags = []
        owner_tag =  {
            'key': 'Owner',
            'value': 'NetworkAccountAdmin'
        }
        account_tag = {
            'key': 'AccountId',
            'value': member_account
        }
        region_tag = {
            'key': 'AccountRegion',
            'value': member_region
        }
        workload_tag = {
            'key': 'Workload',
            'value': workload
        }
        workload_id_tag = {
            'key': 'WorkloadId',
            'value': workload_id
        }
        share_tags.append(owner_tag)
        share_tags.append(account_tag)
        share_tags.append(region_tag)
        share_tags.append(workload_tag)
        share_tags.append(workload_id_tag)
        pool_arn = get_pool_arn(pool_id)
        ram_client = session.client('ram')
        response = ram_client.create_resource_share(
            name=share_name,
            resourceArns=[ pool_arn ],
            principals=[ member_account ],
            tags=share_tags)
        share_arn = response['resourceShare']['resourceShareArn']
        print('Pool: {} shared with Resource Share Arn: {}'.format(pool_arn, share_arn))
        return share_arn
    except Exception as e:
        print(f'failed in create_resource_share(..): {e}')
        print(str(e))
        raise e

def unshare_pool(event):
    resProps = event['ResourceProperties']
    member_account = resProps['member_account']
    member_region = resProps['member_region']
    workload = resProps['workload_type']
    workload_id = resProps['workload_id']
    share_name = '{}-{}-{}-{}'.format(member_account, member_region, workload, workload_id)
    try:
        ram_client = session.client('ram')
        response = ram_client.get_resource_shares(
            resourceOwner='SELF',
            name=share_name,
            resourceShareStatus='ACTIVE')
        if 'resourceShares' in response:
            shareArn = response['resourceShares'][0]['resourceShareArn']
            ram_client.delete_resource_share(resourceShareArn=shareArn)
            if is_resource_unshared(event):
                print('Resource Share: {} deleted'.format(shareArn))
    except Exception as e:
        print(f'failed in delete_resource_share(..): {e}')
        print(str(e))
        raise e

def get_shared_resource(event):
    resProps = event['ResourceProperties']
    member_account = resProps['member_account']
    member_region = resProps['member_region']
    workload = resProps['workload_type']
    workload_id = resProps['workload_id']
    share_name = '{}-{}-{}-{}'.format(member_account, member_region, workload, workload_id)
    try:
        ram_client = session.client('ram')
        response = ram_client.get_resource_shares(resourceOwner='SELF', name=share_name)
        if 'resourceShares' in response:
            return response['resourceShares'][0]
    except Exception as e:
        print(f'failed in get_resource_shares(..):{e}')
        print(str(e))
        raise e

def is_resource_unshared(event):
    unshared = False
    i = int(1)
    while (i < 60):
        try:
            resource = get_shared_resource(event)
            status = resource['status']
            if status == 'DELETED':
                unshared = True
                break
            i = i + 1
            print('wait 10 seconds')
            time.sleep(10)
        except Exception as e:
            print(f'failed in get_shared_resource(..): {e}')
            print(str(e))
            raise e
    return unshared

def create_operation(event, context):
    try:
        ec2_client = session.client('ec2')
        resProps  = event['ResourceProperties']
        member_region = resProps['member_region']
        member_account = resProps['member_account']
        workload = resProps['workload_type']
        workload_id = resProps['workload_id']
        netmaskLength = int(resProps['netmask_length'])
        parent_pool_id = get_parent_pool(ec2_client, member_region, workload)
        print('parent_pool_id = '+parent_pool_id)
        private_scope = get_private_scope(ec2_client)
        print('private_scope  = '+private_scope)
        pool_id = create_pool(ec2_client, parent_pool_id, member_account, member_region, private_scope, workload, workload_id)
        print('pool_id = '+pool_id)
        if is_pool_created(member_region, pool_id):
            provisionedCidr = provision_cidr(member_region, parent_pool_id, pool_id, netmaskLength)
            if is_cidr_provisioned(pool_id, provisionedCidr):
                # do not allocate. This is done by member account
                #allocate_cidr(member_region, pool_id, netmaskLength)
                share_arn = share_pool(event, pool_id)
                responseData = {
                    'account': member_account,
                    'region': member_region,
                    'pool': pool_id,
                    'cidr': provisionedCidr,
                    'resourceShareArn': share_arn,
                    'status': 'created'
                }
                send_response(event, context, 'SUCCESS', responseData)
    except Exception as e:
        LOGGER.error(f'failed in create_operation(..): {e}')
        LOGGER.error(str(e))
        responseData = {
            'exc_info': str(e)
        }
        send_response(event, context, 'FAILED', responseData)

def delete_operation(event, context):
    try:
        resProps = event['ResourceProperties']
        member_account = resProps['member_account']
        member_region = resProps['member_region']
        ec2_client = session.client('ec2')
        private_scope = get_private_scope(ec2_client)
        print('private_scope  = '+private_scope)
        pool_id = get_pool_id(event)
        unshare_pool(event)
        cidrs = deprovision_cidrs(ec2_client, member_region, pool_id, private_scope)
        delete_pool(ec2_client, pool_id)
        responseData = {
            'account': member_account,
            'pool': pool_id,
            'cidr': cidrs,
            'status': 'deleted'
        }
        send_response(event, context, 'SUCCESS', responseData)
    except Exception as e:
        LOGGER.error(f'failed in delete_operation(..): {e}')
        LOGGER.error(str(e))
        responseData = {
            'exc_info': str(e)
        }
        send_response(event, context, 'FAILED', responseData)

def lambda_handler(event, context):
    print(f"REQUEST RECEIVED: {json.dumps(event, default=str)}")
    responseData = {}
    if 'RequestType' in event:
        if event['RequestType'] == 'Create':
            create_operation(event, context)
        elif event['RequestType'] == 'Delete':
            delete_operation(event, context)
        else:
           send_response(event, context, 'SUCCESS', responseData)

#def main():
#    event = {
#        'RequestType': 'Delete',
#        'ResourceProperties': {
#            'member_account': '172489758104',
#            'member_region': 'ap-northeast-1',
#            'workload_type': 'Dev',
#            'netmask_length': 24
#        }
#    }
#    context = {}
#    lambda_handler(event, context)

#if __name__ == '__main__':
#    main()
