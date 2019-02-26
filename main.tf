provider "aws" {
  region  = "eu-west-1"
  version = "1.14"
}

# Support data
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

variable "slack_hook_url" {
  description = "Slack hook url with permissions to SLACK_CHANNEL"
  type        = "string"
}

variable "vpc_id" {
  description = "The key to decrypt env variables"
  type        = "string"
}

variable "kms_id" {
  description = "The KMS key to decrypt env variables"
  type        = "string"
}

variable "subnet_ids" {
  description = "List of subnets for your lambda function"
  type        = "list"
}

data "aws_iam_policy_document" "kms" {
  statement {
    actions = ["kms:Decrypt"]
    effect  = "Allow"

    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/${var.kms_id}",
    ]
  }
}

variable "config_bucket" {
  description = "the s3 bucket that holds env configurations"
  type        = "string"
}

variable "pipeline_bucket" {
  description = "the s3 bucket that holds pipeline artifacts"
  type        = "string"
}

resource "aws_security_group" "lambda" {
  name        = "lambda_invoke-k8s-deploy_security_group"
  description = "lambda to invoke k8s api security group"
  vpc_id      = "${var.vpc_id}"

  # Allow all outgoing traffic (through NAT)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    Name        = "lambda-k8s-deploy-sg"
    Terraformed = "true"
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "aws" {
  statement {
    actions = [
      "s3:GetObject",
      "s3:HeadObject",
      "s3:ListBucket",
    ]

    effect = "Allow"

    resources = [
      "arn:aws:s3:::${var.config_bucket}",
      "arn:aws:s3:::${var.config_bucket}/*",
      "arn:aws:s3:::${var.pipeline_bucket}",
      "arn:aws:s3:::${var.pipeline_bucket}/*",
    ]
  }

  statement {
    actions = [
      "ecr:BatchGetImage",
      "ecr:PutImage",
    ]

    effect = "Allow"

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "codepipeline:PutJobSuccessResult",
      "codepipeline:PutJobFailureResult",
    ]

    effect    = "Allow"
    resources = ["*"]
  }

  statement {
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
    ]

    effect    = "Allow"
    resources = ["${aws_dynamodb_table.kubernetes_deploy.arn}"]
  }
}

resource "aws_iam_policy" "kms" {
  name        = "kms_decrypt_k8s_deploy_lambda"
  description = "KMS Decrypt"
  policy      = "${data.aws_iam_policy_document.kms.json}"
}

resource "aws_iam_role" "lambda" {
  name               = "lambda_slack_notify_k8s_deploy"
  assume_role_policy = "${data.aws_iam_policy_document.lambda.json}"
}

resource "aws_iam_policy" "lambda_aws" {
  name        = "lambda_slack_notify_k8s_deploy_aws"
  description = "read deployment manifests and config"
  policy      = "${data.aws_iam_policy_document.aws.json}"
}

resource "aws_iam_policy_attachment" "access_aws_resources" {
  name       = "allow lambda instance role access resources"
  roles      = ["${aws_iam_role.lambda.name}"]
  policy_arn = "${aws_iam_policy.lambda_aws.arn}"
}

resource "aws_iam_policy_attachment" "kms_attach_instance_role" {
  name       = "allow lambda instance role to decrypt kms"
  roles      = ["${aws_iam_role.lambda.name}"]
  policy_arn = "${aws_iam_policy.kms.arn}"
}

resource "aws_iam_role_policy_attachment" "basic_lambda_execution" {
  role       = "${aws_iam_role.lambda.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

data "aws_kms_ciphertext" "slack_url" {
  key_id    = "${var.kms_id}"
  plaintext = "${var.slack_hook_url}"
}

resource "aws_lambda_function" "k8s_deploy" {
  filename      = "./function_payload.zip"
  function_name = "notify_k8s_deploy"
  handler       = "handler.lambda_handler"
  timeout       = "500"
  memory_size   = "512"

  vpc_config {
    subnet_ids         = "${var.subnet_ids}"
    security_group_ids = ["${aws_security_group.lambda.id}"]
  }

  role             = "${aws_iam_role.lambda.arn}"
  source_code_hash = "${base64sha256(file("./function_payload.zip"))}"
  runtime          = "python3.6"
  kms_key_arn      = "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/${var.kms_id}"

  environment {
    variables = {
      APP_CONFIG_BUCKET    = "${var.config_bucket}"
      DEPLOY_CONFIG_BUCKET = "${var.config_bucket}"
      DEPLOY_CONFIG_FOLDER = "k8s_deployer"
      DOCKER_REGISTRY      = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com"
      SLACK_HOOK_URL       = "${data.aws_kms_ciphertext.slack_url.ciphertext_blob}"
    }
  }
}

resource "aws_dynamodb_table" "kubernetes_deploy" {
  name           = "kubernetes_deploy"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "Application"
  range_key      = "Env"

  attribute {
    name = "Application"
    type = "S"
  }

  attribute {
    name = "Env"
    type = "S"
  }
}
