import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')

def lambda_handler(event, context):
    """
    Automatically blocks public access on any S3 bucket
    that is detected as publicly accessible by AWS Config.
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Parse the SNS message
    message = json.loads(event['Records'][0]['Sns']['Message'])
    
    # Get the non-compliant resource (S3 bucket name)
    bucket_name = message['detail']['resourceId']
    
    logger.info(f"Remediating bucket: {bucket_name}")

    try:
        # Block all public access on the bucket
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls':       True,
                'IgnorePublicAcls':      True,
                'BlockPublicPolicy':     True,
                'RestrictPublicBuckets': True
            }
        )

        logger.info(f"Successfully blocked public access on {bucket_name}")

        return {
            'statusCode': 200,
            'body': f'Successfully remediated bucket: {bucket_name}'
        }

    except Exception as e:
        logger.error(f"Error remediating bucket {bucket_name}: {str(e)}")
        raise e