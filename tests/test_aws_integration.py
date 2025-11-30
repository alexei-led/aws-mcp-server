"""Test to verify AWS integration setup."""

import pytest


@pytest.mark.integration
@pytest.mark.asyncio
async def test_aws_bucket(aws_s3_bucket):
    """Test that AWS bucket fixture works."""
    # We need to manually extract the bucket name from the async generator
    bucket_name = None
    async for name in aws_s3_bucket:
        bucket_name = name
        break

    print(f"AWS bucket fixture returned: {bucket_name}")
    assert bucket_name is not None
    assert isinstance(bucket_name, str)
    assert len(bucket_name) > 0
