provider "aws" {
  region = var.aws_region
  profile = "terraform-bootstrap-admin"
}

data "aws_caller_identity" "current" {}

# Create IAM policy for VPC management
resource "aws_iam_policy" "terraform_vpc" {
  name        = "terraform-vpc-policy"
  description = "Policy for Terraform VPC management"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc",
          "ec2:DeleteVpc",
          "ec2:ModifyVpcAttribute",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:DescribeSubnets",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:DescribeRouteTables",
          "ec2:AssociateRouteTable",
          "ec2:DisassociateRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:DescribeRoutes",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:DescribeInternetGateways",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:DescribeNatGateways",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeNetworkAcls",
          "ec2:CreateNetworkAcl",
          "ec2:DeleteNetworkAcl",
          "ec2:ModifyNetworkAclEntry",
          "ec2:CreateNetworkAclEntry",
          "ec2:DeleteNetworkAclEntry",
          "ec2:AllocateAddress",
          "ec2:ReleaseAddress",
          "ec2:DescribeAddresses",
          "ec2:DescribeAddressesAttribute",
           "ec2:CreateFlowLogs",
           "ec2:DescribeFlowLogs",
           "ec2:DeleteFlowLogs"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:DeleteBucketPolicy"
        ]
        Resource = "arn:aws:s3:::video-analysis-terraform-state-sean/vpc/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem",
          "dynamodb:UpdateItem",
          "dynamodb:Scan",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:*:table/video-analysis-terraform-locks"
      },
      {
        Effect = "Allow"
        Action = [
         "iam:GetRole",
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:PassRole",
          "iam:DeleteRole",
          "iam:ListRoles",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy",
          "iam:DetachRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:AttachRolePolicy",  
          "iam:DetachRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:ListPolicyVersions"
        ]
        "Resource": "arn:aws:iam::454778920769:role/vpc-flow-log-role-*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:DeletePolicy",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListPolicies",
          "iam:ListPolicyVersions",
          "iam:TagPolicy",
          "iam:UntagPolicy" 
        ]
        "Resource": "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:ListTagsForResource",
          "logs:ListTagsLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:PutRetentionPolicy",
          "logs:TagResource"
        ]
        Resource = [
          "arn:aws:logs:us-east-1:454778920769:log-group:/aws/vpc-flow-log/*",
          "arn:aws:logs:us-east-1:454778920769:log-group:/aws/vpc-flow-log/*:log-stream:*",
          "arn:aws:logs:us-east-1:454778920769:log-group:*",
          "arn:aws:logs:us-east-1:454778920769:log-group::log-stream:",
          "arn:aws:logs:us-east-1:454778920769:log-group:*"
        ]
      }
    ]
  })
}

# Create IAM user for VPC management
resource "aws_iam_user" "terraform_vpc" {
  name = "terraform-vpc-automation"
}

# Attach policy to user
resource "aws_iam_user_policy_attachment" "terraform_vpc" {
  user       = aws_iam_user.terraform_vpc.name
  policy_arn = aws_iam_policy.terraform_vpc.arn
}

# Create access key for VPC user
resource "aws_iam_access_key" "terraform_vpc" {
  user = aws_iam_user.terraform_vpc.name
}

# variables.tf
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# outputs.tf
output "vpc_user_access_key" {
  value     = aws_iam_access_key.terraform_vpc.id
  sensitive = true
}

output "vpc_user_secret_key" {
  value     = aws_iam_access_key.terraform_vpc.secret
  sensitive = true
}

# backend.tf
terraform {
  backend "s3" {
    bucket         = "video-analysis-terraform-state-sean"
    key            = "iam/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "video-analysis-terraform-locks"
    encrypt        = true
  }
}