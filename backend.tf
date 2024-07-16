// root/backend.tf
terraform {
  backend "s3" {
    bucket         = "adityadhopade-sample-s3-bucket"
    key            = "Versioning/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-lock-table"
    encrypt        = true
  }
}
