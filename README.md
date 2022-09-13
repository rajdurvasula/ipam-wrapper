# CDK TypeScript project - IPAM Pool Allocation - AWS Service Catalog Product

This is a automation project using CDK development with TypeScript.

The `cdk.json` file tells the CDK Toolkit how to execute your app.

## Purpose
Setup Service Catalog Portfolio, Product for allocation of IPAM Pool to a Member Account
- Creates Portfolio
- Creates Product

## Setup
- The access to Service Catalog Portfolio is granted access to End Users / IAM Group: sc-endusers
- Default End User Id: scenduser
> To change default End User Id, update `cdk.json`

## Resources Configured
- Service Catalog Portfolio
- Service Catalog Product
- IAM Role for IAM actions
- IAM Role for Lambda actions
- IAM Role for CloudFormation actions

## Dependencies
- Upload `src\create_account_pool.yaml` to S3 Bucket
- Upload `src\create_account_pool.zip` to S3 Bucket

## Provisioning Service Catalog Product
- Login to Networt Account as `SCEndUser` 
- In Service Catalog console, select the `Product`
- Click 'Actions -> Launch Product'
- Enter Member Account Id (**recipient of IPAM Pool**)
- Select Member Account Region
- Enter S3 Bucket
- Select Workload type
- Enter unique id for this provisioning request
- Submit Provisioning Product

> - To verify progress of Provisioning operation, login to SharedNetwork AWS Console as *Administrator*
> - For each provisioned product, a CloudWatch Log Group is created with name pattern */aws/lambda/AccountId-PoolAllocator-WorkloadId*

### Result
- Product is provisioned
- IPAM Pool is created
- IPAM Pool is shared with Member Account
- Member Account user can **create VPC in the specified region using provisioned IPAM Pool**

## Deprovisioning Service Catalog Product
- Login to Networt Account as `SCEndUser`
- In Service Catalog console, select the `Provisioned Product`
- Click 'Actions -> Terminate'

### Deprovisioning considerations
- Login to SharedNetwork Account AWS Console as *Administrator* user
- Ensure CIDR resouces are listed in the provisioned IPAM Pool
- Login to SharedNetwork Account AWS Console as *scenduser*
- Terminate the provisioned product

> - De-allocation, Deprovisioning of IPAM pool takes several minutes
> - To verify progress of Deprovisioning operation, login to SharedNetwork AWS Console as *Administrator*
> - For each provisioned product, check the log stream in CloudWatch Log Group with name pattern */aws/lambda/MemberAccountId-PoolAllocator-WorkloadId*

### Result
- Provisioned product will be unshared
  - Verify RAM Console
- IPAM Pool CIDR will be de-allocated
  - *Ensure no CIDR allocations exist*
    - For Example: No VPCs (or other AWS resources) using the IPAM Pool
- IPAM Pool CIDR will be de-provisioned
  - *CIDR will be available for any future provisioning*
- IPAM Pool will be deleted
- Provisioned product will be deleted

## Useful commands

* `npm install`     downloads dependencies
* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests **does not work**
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
