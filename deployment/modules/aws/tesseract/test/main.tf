terraform {
  backend "s3" {}
}

variable "availability_zone_id" {
  type = string
}

module "storage" {
  source = "../../storage"

  availability_zone_id = var.availability_zone_id
  prefix_name        = var.prefix_name
  base_name          = var.base_name
  region             = var.region
  ephemeral          = var.ephemeral
  create_antispam_db = false
}

module "secretsmanager" {
  source = "../../secretsmanager"

  base_name                                  = var.base_name
  region                                     = var.region
  tls_private_key_ecdsa_p256_public_key_pem  = module.insecuretlskey.tls_private_key_ecdsa_p256_public_key_pem
  tls_private_key_ecdsa_p256_private_key_pem = module.insecuretlskey.tls_private_key_ecdsa_p256_private_key_pem
}

# [WARNING]
# This module will store unencrypted private keys in the OpenTofu state file.
# DO NOT use this for production logs.
module "insecuretlskey" {
  source = "../../insecuretlskey"
}
