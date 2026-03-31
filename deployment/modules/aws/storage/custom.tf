resource "aws_db_subnet_group" "db" {
  name = "tesseract-ct-db-subnet-group"
  subnet_ids = [ "subnet-052964b05ba075366", "subnet-036f5d55eab916d21", "subnet-0dae520a89a36e151" ]
}