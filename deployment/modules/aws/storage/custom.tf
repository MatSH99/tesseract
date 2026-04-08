// resource "aws_db_subnet_group" "db" {
//  name = "tesseract-ct-db-subnet-group"
//  subnet_ids = [ "subnet-052964b05ba075366", "subnet-036f5d55eab916d21", "subnet-0dae520a89a36e151" ]
//}

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