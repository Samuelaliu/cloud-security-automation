import boto3
import json
import sys
import time

def setup_security_automation():
    """
    Sets up the complete cloud security automation stack:
    - SNS topic for alerts
    - AWS Config recorder
    - Config rules for S3 and Security Groups
    """

    region = 'us-east-1'
    account_id = boto3.client('sts').get_caller_identity()['Account']

    sns_client    = boto3.client('sns',    region_name=region)
    config_client = boto3.client('config', region_name=region)
    iam_client    = boto3.client('iam')
    s3_client     = boto3.client('s3',     region_name=region)

    print("Setting up Cloud Security Automation...")
    print(f"Account: {account_id} | Region: {region}")
    print("-" * 50)

    # Step 1: Create SNS Topic for alerts
    print("Creating SNS alert topic...")
    sns_response = sns_client.create_topic(Name='security-alerts')
    sns_arn = sns_response['TopicArn']
    print(f"SNS Topic created: {sns_arn}")

    # Step 2: Subscribe your email to SNS
    email = input("\nEnter your email for security alerts: ")
    sns_client.subscribe(
        TopicArn=sns_arn,
        Protocol='email',
        Endpoint=email
    )
    print(f"Check your email ({email}) and confirm the subscription!")

    # Step 3: Create S3 bucket for Config logs
    bucket_name = f"config-logs-{account_id}-{region}"
    print(f"\nCreating S3 bucket for Config logs: {bucket_name}")

    try:
        s3_client.create_bucket(Bucket=bucket_name)
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        print(f"Bucket already exists: {bucket_name}")

    # Set bucket policy for AWS Config
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}"
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*"
            }
        ]
    }

    s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(bucket_policy)
    )
    print(f"S3 bucket configured for Config logs")

    # Step 4: Create IAM role for AWS Config
    print("\nCreating IAM role for AWS Config...")
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }

    try:
        role_response = iam_client.create_role(
            RoleName='AWSConfigRole-Samuel',
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        role_arn = role_response['Role']['Arn']

        iam_client.attach_role_policy(
            RoleName='AWSConfigRole-Samuel',
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWS_ConfigRole'
        )
        print(f"IAM role created: {role_arn}")
        print("Waiting 15 seconds for IAM role to propagate...")
        time.sleep(15)

    except iam_client.exceptions.EntityAlreadyExistsException:
        role_arn = f"arn:aws:iam::{account_id}:role/AWSConfigRole-Samuel"
        print(f"IAM role already exists: {role_arn}")

    # Step 5: Set up AWS Config Recorder
    print("\nSetting up AWS Config recorder...")
    config_client.put_configuration_recorder(
        ConfigurationRecorder={
            'name': 'default',
            'roleARN': role_arn,
            'recordingGroup': {
                'allSupported': True,
                'includeGlobalResourceTypes': True
            }
        }
    )

    config_client.put_delivery_channel(
        DeliveryChannel={
            'name': 'default',
            's3BucketName': bucket_name,
            'snsTopicARN': sns_arn
        }
    )

    config_client.start_configuration_recorder(
        ConfigurationRecorderName='default'
    )
    print("AWS Config recorder started!")

    # Step 6: Create Config Rules
    print("\nCreating security compliance rules...")

    # Rule 1: S3 buckets must not be public
    config_client.put_config_rule(
        ConfigRule={
            'ConfigRuleName': 's3-bucket-public-access-prohibited',
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': 'S3_BUCKET_PUBLIC_READ_PROHIBITED'
            }
        }
    )
    print("Rule created: S3 buckets must not be publicly readable")

    # Rule 2: Security groups must not allow unrestricted SSH
    config_client.put_config_rule(
        ConfigRule={
            'ConfigRuleName': 'restricted-ssh',
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': 'INCOMING_SSH_DISABLED'
            }
        }
    )
    print("Rule created: SSH must not be open to the world")

    # Rule 3: MFA must be enabled for root account
    config_client.put_config_rule(
        ConfigRule={
            'ConfigRuleName': 'root-account-mfa-enabled',
            'Source': {
                'Owner': 'AWS',
                'SourceIdentifier': 'ROOT_ACCOUNT_MFA_ENABLED'
            }
        }
    )
    print("Rule created: Root account must have MFA enabled")

    print("\n" + "=" * 50)
    print("Security Automation Setup Complete!")
    print("=" * 50)
    print(f"SNS Topic ARN: {sns_arn}")
    print(f"Config Logs Bucket: {bucket_name}")
    print("\nNext steps:")
    print("1. Confirm your email subscription")
    print("2. Deploy the Lambda functions")
    print("3. Run the compliance report")

if __name__ == "__main__":
    setup_security_automation()