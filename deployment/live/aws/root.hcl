locals {
  env           = path_relative_to_include()
  region        = get_env("AWS_REGION", "eu-west-1")
  base_name     = get_env("TESSERA_BASE_NAME", "${local.env}-static-ct")
  origin_suffix = get_env("TESSERA_ORIGIN_SUFFIX", "")
  prefix_name   = "${get_aws_account_id()}"
  ephemeral     = true

  az_id         = get_env("AZ_ID", "euw1-az1")
}

remote_state {
  backend = "s3"

  config = {
    region = local.region
    bucket = "${local.prefix_name}-${local.base_name}-terraform-state"
    key    = "terraform.tfstate"
    s3_bucket_tags = {
      name = "terraform_state_storage"
    }
    use_lockfile = true
  }
}
