terraform { required_version = ">= 1.5" }
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "public_admin" {
  name = "public-admin"
  ingress { from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }
  ingress { from_port = 0 to_port = 0 protocol = "-1" cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_s3_bucket" "customer_data" { bucket = "cloudsentinel-demo-data" acl = "public-read" }
resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket = "cloudsentinel-demo-data"
  block_public_acls = false
  block_public_policy = false
  ignore_public_acls = false
  restrict_public_buckets = false
}
resource "aws_db_instance" "production" {
  identifier = "production-db"
  engine = "postgres"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "demo"
  password = "DEMO_ONLY_DO_NOT_USE"
  publicly_accessible = true
  storage_encrypted = false
  backup_retention_period = 1
  deletion_protection = false
  skip_final_snapshot = true
}
resource "aws_iam_policy" "admin" {
  name = "unrestricted-admin"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
resource "aws_iam_access_key" "demo" { user = "demo-user" }
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 8
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers = false
  require_symbols = false
  max_password_age = 180
}
resource "aws_kms_key" "data" { description = "demo" enable_key_rotation = false }
resource "aws_ebs_volume" "logs" { availability_zone = "us-east-1a" size = 10 encrypted = false }
resource "aws_lb" "public" { name = "demo-alb" internal = false load_balancer_type = "application" enable_deletion_protection = false subnets = ["subnet-demo"] }
resource "aws_instance" "web" { ami = "ami-demo" instance_type = "t3.micro" associate_public_ip_address = true }
resource "aws_lambda_function" "processor" {
  function_name = "demo-processor" role = "arn:aws:iam::123456789012:role/demo" handler = "index.handler" runtime = "python3.12" filename = "demo.zip"
  environment { variables = { API_TOKEN = "DEMO_PLACEHOLDER" } }
}
resource "aws_secretsmanager_secret" "app" { name = "demo/app" recovery_window_in_days = 0 }
resource "aws_eks_cluster" "main" { name = "demo" role_arn = "arn:aws:iam::123456789012:role/demo" version = "1.30" vpc_config { subnet_ids = ["subnet-demo"] endpoint_public_access = true } }
resource "aws_ecs_task_definition" "worker" { family = "worker" container_definitions = jsonencode([{ name = "worker", image = "example/demo:latest", privileged = true, memory = 128 }]) }
resource "aws_sqs_queue" "jobs" { name = "demo-jobs" }
resource "aws_sns_topic" "alerts" { name = "demo-alerts" }
resource "aws_dynamodb_table" "sessions" { name = "demo-sessions" billing_mode = "PAY_PER_REQUEST" hash_key = "id" attribute { name = "id" type = "S" } point_in_time_recovery { enabled = false } }
resource "aws_default_security_group" "default" { vpc_id = "vpc-demo" ingress { protocol = "-1" self = true from_port = 0 to_port = 0 } egress { protocol = "-1" from_port = 0 to_port = 0 cidr_blocks = ["0.0.0.0/0"] } }
resource "aws_cloudwatch_log_group" "app" { name = "/demo/app" retention_in_days = 7 }
resource "aws_api_gateway_stage" "prod" { deployment_id = "demo" rest_api_id = "demo" stage_name = "prod" }
