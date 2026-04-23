import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client('ec2')

def lambda_handler(event, context):
    """
    Automatically removes dangerous open ingress rules
    from security groups that allow unrestricted access
    on sensitive ports.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Parse the SNS message
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Get the non-compliant security group ID
    sg_id = message['detail']['resourceId']

    logger.info(f"Remediating security group: {sg_id}")

    try:
        # Get the security group details
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg = response['SecurityGroups'][0]

        # Find dangerous rules — open to the world (0.0.0.0/0) on sensitive ports
        dangerous_ports = [22, 3389, 3306, 5432, 27017]
        rules_to_remove = []

        for rule in sg['IpPermissions']:
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if rule.get('FromPort') in dangerous_ports:
                        rules_to_remove.append(rule)
                        logger.info(f"Found dangerous rule: port {rule.get('FromPort')} open to world")

        # Remove the dangerous rules
        if rules_to_remove:
            ec2_client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=rules_to_remove
            )
            logger.info(f"Removed {len(rules_to_remove)} dangerous rules from {sg_id}")
        else:
            logger.info(f"No dangerous rules found in {sg_id}")

        return {
            'statusCode': 200,
            'body': f'Successfully remediated security group: {sg_id}'
        }

    except Exception as e:
        logger.error(f"Error remediating security group {sg_id}: {str(e)}")
        raise e