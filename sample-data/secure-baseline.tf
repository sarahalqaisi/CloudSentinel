resource "aws_kms_key" "main" { enable_key_rotation = true }
resource "aws_cloudtrail" "organization" { name = "org-trail" enable_log_file_validation = true s3_bucket_name = "secure-audit-logs" }
resource "aws_flow_log" "main" { iam_role_arn = "arn:aws:iam::123456789012:role/flow" log_destination = "arn:aws:logs:us-east-1:123456789012:log-group:flow" traffic_type = "ALL" vpc_id = "vpc-demo" }
resource "aws_config_configuration_recorder" "main" { name = "default" role_arn = "arn:aws:iam::123456789012:role/config" }
resource "aws_guardduty_detector" "main" { enable = true }
resource "aws_securityhub_account" "main" {}
resource "aws_s3_bucket" "private" { bucket = "secure-demo-bucket" acl = "private" }
resource "aws_s3_bucket_server_side_encryption_configuration" "private" { bucket = "secure-demo-bucket" rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" kms_master_key_id = aws_kms_key.main.arn } } }
resource "aws_s3_bucket_versioning" "private" { bucket = "secure-demo-bucket" versioning_configuration { status = "Enabled" } }
