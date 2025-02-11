provider "aws" {
  region = var.aws_region
}

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
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:CreateRouteTable",
          "ec2:DeleteRouteTable",
          "ec2:CreateRoute",
          "ec2:DeleteRoute",
          "ec2:CreateInternetGateway",
          "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway",
          "ec2:DetachInternetGateway",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::video-analysis-terraform-state-sean/vpc/*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:*:table/video-analysis-terraform-locks"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetRole"
        ]
        Resource = "arn:aws:iam::454778920769:role/vpc-flow-log-role-20250207063811604700000001"
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