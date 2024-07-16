terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.57.0"
    }

    null = {
      source  = "hashicorp/null"
      version = "3.2.2"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_group" "admin_group" {
  name = "admin-group"
}

resource "aws_iam_group_policy_attachment" "admin_group_policy_attachment" {
  group      = aws_iam_group.admin_group.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

#NEWLY ADDED
data "aws_caller_identity" "current" {}

module "admin_user_1" {
  source           = "./iam-group-users"
  user_name        = "admin-user-1"
  admin_group_name = aws_iam_group.admin_group.name
  account_id       = data.aws_caller_identity.current.account_id
}

module "admin_user_2" {
  source           = "./iam-group-users"
  user_name        = "admin-user-2"
  admin_group_name = aws_iam_group.admin_group.name
  account_id       = data.aws_caller_identity.current.account_id
}

module "admin_user_3" {
  source           = "./iam-group-users"
  user_name        = "admin-user-3"
  admin_group_name = aws_iam_group.admin_group.name
  account_id       = data.aws_caller_identity.current.account_id
}

output "admin_user_1_access_key_id" {
  value = module.admin_user_1.aws_access_key_id
}

output "admin_user_1_secret_access_key" {
  value     = module.admin_user_1.aws_secret_access_key
  sensitive = true
}

output "admin_user_1_initial_password" {
  value     = module.admin_user_1.initial_password
  sensitive = true
}


# # Attach console access policy to admin-user-1
# resource "aws_iam_policy_attachment" "admin_user_1_console_access" {
#   name       = "admin-user-1-console-access"
#   users      = [aws_iam_user.admin_user_1.name]
#   policy_arn = aws_iam_policy.console_access_policy.arn
# }

output "admin_user_2_access_key_id" {
  value = module.admin_user_2.aws_access_key_id
}

output "admin_user_2_secret_access_key" {
  value     = module.admin_user_2.aws_secret_access_key
  sensitive = true
}

output "admin_user_2_initial_password" {
  value     = module.admin_user_2.initial_password
  sensitive = true
}

output "admin_user_3_access_key_id" {
  value = module.admin_user_3.aws_access_key_id
}

output "admin_user_3_secret_access_key" {
  value     = module.admin_user_3.aws_secret_access_key
  sensitive = true
}

output "admin_user_3_initial_password" {
  value     = module.admin_user_3.initial_password
  sensitive = true
}
