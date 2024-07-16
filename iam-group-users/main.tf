provider "aws" {
  region = "us-east-1"
}

# Generate Random Password for users

resource "random_password" "admin_user_password" {
  length           = 10
  special          = true
  upper            = true
  numeric          = true
  override_special = "_%&@#/"
}

resource "aws_iam_account_password_policy" "password_policy" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 1095 // never expire (100 Years)
  password_reuse_prevention      = 5
  hard_expiry                    = false
}

# Create IAM user
resource "aws_iam_user" "admin_user" {
  name = var.user_name
  # Delete user even if it has non-Terraform-managed IAM access keys, login profile or MFA devices
  force_destroy = true
}

# Create access keys for the IAM user
resource "aws_iam_access_key" "admin_user_key" {
  user = aws_iam_user.admin_user.name
}

# Attach the AdministratorAccess policy to the user
resource "aws_iam_user_policy_attachment" "admin_user_policy_attachment" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Add the user to the group
resource "aws_iam_user_group_membership" "admin_user_group_membership" {
  user   = aws_iam_user.admin_user.name
  groups = [var.admin_group_name]
}

# Create a login profile for the user to require a password change at first login
resource "aws_iam_user_login_profile" "admin_user_login_profile" {
  user                    = aws_iam_user.admin_user.name
  password_length         = 10
  password_reset_required = true
}

# #GETTING ARN OF Existing Policy

# data "aws_iam_policy" "existing_console_access_policy" {
#   arn = "arn:aws:iam::533267393507:policy/NewConsoleAccessPolicy" # Replace with actual ARN of Policy
# }

# resource "aws_iam_user_policy_attachment" "admin_user_policy_attachment_console" {
#   user       = aws_iam_user.admin_user.name
#   policy_arn = "arn:aws:iam::533267393507:policy/ConsoleAccessPolicy"
# }

# # Create the IAM Policy for `AWS CONSOLE ACCESS`
# resource "aws_iam_policy" "console_access_policy" {
#   name        = "ConsoleAccessPolicy"
#   description = "Allows console access for IAM users"
#   #policy_arn  = data.aws_iam_policy.existing_console_access_policy
#   policy = data.aws_iam_policy_document.console_access_policy_document.json
#   #depends_on = [data.aws_iam_policy_document.console_access_policy]

#   lifecycle {
#     prevent_destroy = false
#     # ignore_changes = [
#     #   policy
#     # ]
#   }
# }

# Define IAM policy document allowing console access
# data "aws_iam_policy_document" "console_access_policy_document" {
#   statement {
#     effect    = "Allow"
#     actions   = ["sts:AssumeRole"]
#     resources = ["*"]
#   }
# }

# Local-Exec provisioner to check IAM policy existence
# resource "null_resource" "check_policy_existence" {
#   provisioner "local-exec" {
#     command = <<EOT
#       aws iam get-policy --policy-arn ${aws_iam_policy.console_access_policy.arn} >/dev/null 2>&1
#       if [ $? -eq 0 ]; then
#         echo "IAM policy exists."
#       else
#         echo "IAM policy does not exist."
#       fi
#     EOT
#   }

#   depends_on = [aws_iam_policy.console_access_policy]
# }

# Output the access key ID and secret access key
output "aws_access_key_id" {
  value = aws_iam_access_key.admin_user_key.id
}

output "aws_secret_access_key" {
  value     = aws_iam_access_key.admin_user_key.secret
  sensitive = true
}

# Output the generated password
output "initial_password" {
  value     = random_password.admin_user_password.result
  sensitive = true
}


### TRY 2

# Create a policy for console access
# data "aws_iam_policy_document" "console_access_policy" {
#   statement {
#     effect = "Allow"
#     actions = [
#       "iam:CreateLoginProfile",
#       "iam:DeleteLoginProfile",
#       "iam:GetLoginProfile",
#       "iam:UpdateLoginProfile",
#       "iam:ListUsers"
#     ]
#     resources = ["*"]
#   }
# }

# Define IAM policy document allowing console access
data "aws_iam_policy_document" "console_access_policy" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole",
      "iam:PassRole",
      "iam:ListRoles",
      "iam:ListRolePolicies",
      "iam:ListUsers",
      "iam:GetUser",
      "iam:ListAttachedUserPolicies",
      "iam:ListGroupsForUser",
    "iam:GetUserPolicy"]
    resources = ["*"]
  }
}

# data "aws_iam_policy" "existing_console_access_policy" {
#   name = "NewConsoleAccessPolicy"
#   arn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/NewConsoleAccessPolicy"
# }

data "aws_caller_identity" "current" {}

# Check if Console Access Policy exists
data "aws_iam_policy" "existing_console_access_policy" {
  arn = "arn:aws:iam::${var.account_id}:policy/NewConsoleAccessPolicy"
}

resource "aws_iam_policy" "console_access_policy" {
  count       = data.aws_iam_policy.existing_console_access_policy.id == "" ? 1 : 0
  name        = "NewConsoleAccessPolicy"
  description = "Allows console access for IAM users"
  policy      = data.aws_iam_policy_document.console_access_policy.json

  lifecycle {
    create_before_destroy = true
  }
}



# # Attach the Console Access policy to the user
# resource "aws_iam_user_policy_attachment" "console_access_policy_attachment" {
#   user       = aws_iam_user.admin_user.name
#   policy_arn = aws_iam_policy.console_access_policy.arn
# }

# resource "null_resource" "create_console_access_policy" {
#   provisioner "local-exec" {
#     command = <<EOT
#       aws iam get-policy --policy-arn arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/NewConsoleAccessPolicy >/dev/null 2>&1
#       if [ $? -ne 0 ]; then
#         aws iam create-policy --policy-name NewConsoleAccessPolicy --policy-document '${data.aws_iam_policy_document.console_access_policy.json}'
#       fi
#     EOT
#   }

#   triggers = {
#     policy_check = "${data.aws_iam_policy.existing_console_access_policy.arn}"
#   }
# }

# Attach the Console Access policy to the user
resource "aws_iam_user_policy_attachment" "console_access_policy_attachment" {
  user = aws_iam_user.admin_user.name
  #policy_arn = data.aws_iam_policy.existing_console_access_policy.arn
  #policy_arn = coalesce(data.aws_iam_policy.existing_console_access_policy.arn, aws_iam_policy.console_access_policy[0].arn)
  policy_arn = data.aws_iam_policy.existing_console_access_policy.id != "" ? data.aws_iam_policy.existing_console_access_policy.arn : aws_iam_policy.console_access_policy[0].arn
}

# Output the login URL
output "login_url" {
  value = "https://${var.account_id}.signin.aws.amazon.com/console"
}
