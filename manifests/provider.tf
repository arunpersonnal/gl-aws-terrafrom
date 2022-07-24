terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket = "s3-terraform-backend-state"
    key    = "s3/terraform.tfstate"
    region = "us-west-2"
    dynamodb_table = "aws-s3-remote-terraform-lock"
    encrypt        = true
  }
}  


# Configure the AWS Provider
provider "aws" {
  region                  = "us-east-1"
#  shared_credentials_file = "~/.aws/credentials"
  profile                 = "default"
}