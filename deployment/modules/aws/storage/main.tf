terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.92.0"
    }
    mysql = {
      source  = "petoju/mysql"
      version = "3.0.71"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.region
}

variable "availability_zone_id" {
  type        = string
  description = "The AZ ID where the directory bucket will reside (e.g., euw1-az1)"
}

resource "aws_s3_directory_bucket" "log_bucket" {
  bucket = "${var.prefix_name}-${var.base_name}-bucket--${var.availability_zone_id}--x-s3"

  location {
    name = var.availability_zone_id
    type = "AvailabilityZone"
  }

  force_destroy = var.ephemeral
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "all" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_db_subnet_group" "db" {
  name       = "tesseract-ct-db-subnet-group"
  subnet_ids = data.aws_subnets.all.ids
}

resource "random_password" "master" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]" # Evitiamo caratteri che possono dare noie in bash
}

resource "aws_secretsmanager_secret" "db_pass" {
  name = "${var.base_name}-rds-fixed-password"
}

resource "aws_secretsmanager_secret_version" "db_pass" {
  secret_id     = aws_secretsmanager_secret.db_pass.id
  secret_string = jsonencode({
    username = aws_rds_cluster.log_rds_cluster.master_username
    password = random_password.master.result
    host     = aws_rds_cluster.log_rds_cluster.endpoint
    port     = 3306
  })
}

resource "aws_rds_cluster" "log_rds_cluster" {
  cluster_identifier          = "${var.base_name}-cluster"
  engine                      = "aurora-mysql"
  engine_version              = "8.0"
  database_name               = "tesseract"
//  manage_master_user_password = false
  master_username             = "tesseract"
  master_password             = random_password.master.result
  skip_final_snapshot         = true
  apply_immediately           = true
  db_subnet_group_name = aws_db_subnet_group.db.name
}

resource "aws_rds_cluster_instance" "cluster_instances" {
  count              = 1
  cluster_identifier = aws_rds_cluster.log_rds_cluster.id
  instance_class     = "db.r5.large"
  engine             = aws_rds_cluster.log_rds_cluster.engine
  engine_version     = aws_rds_cluster.log_rds_cluster.engine_version
  identifier         = "${var.base_name}-${count.index + 1}"
  db_subnet_group_name = aws_db_subnet_group.db.name

  force_destroy = var.ephemeral
}

# Data source to get the secret details using the ARN provided by the cluster
data "aws_secretsmanager_secret_version" "db_credentials" {
  # The secret ARN is available in the master_user_secret block (it's a list)
  secret_id = aws_secretsmanager_secret.db_pass.id

  depends_on = [
    aws_rds_cluster.log_rds_cluster,
    aws_rds_cluster_instance.cluster_instances,
    aws_secretsmanager_secret_version.db_pass
  ]
}

# Configure the MySQL provider based on the outcome of
# creating the aws_db_instance.
# This requires that the machine running OpenTofu has access
# to the DB instance created above. This is _NOT_ the case when
# GitHub actions are applying the OpenTofu.
provider "mysql" {
  endpoint = aws_rds_cluster_instance.cluster_instances[0].endpoint
  username = aws_rds_cluster.log_rds_cluster.master_username
  password = jsondecode(data.aws_secretsmanager_secret_version.db_credentials.secret_string)["password"]
}

# Create a second database for antispam.
resource "mysql_database" "antispam_db" {
  name  = "antispam_db"
  count = var.create_antispam_db ? 1 : 0
}
