variable "account_name" {
  type = string
}

variable "namespace" {
  type    = string
}

variable "opsgenie_sns_topic" {
  type = string
}

variable "log_group_name" {
  type = string
}

// CONDITIONALS

variable "enable_root_usage" {
  type    = bool
  default = false
}

variable "enable_security_group_changes" {
  type    = bool
  default = false
}

variable "enable_cloudtrail_cfg_changes" {
  type    = bool
  default = false
}

variable "enable_iam_changes" {
  type    = bool
  default = false
}

variable "enable_unauthorized_api_call" {
  type    = bool
  default = false
}

variable "enable_aws_config_changes" {
  type    = bool
  default = false
}

variable "enable_bucket_policy_changes" {
  type    = bool
  default = false
}

variable "enable_route_table_changes" {
  type    = bool
  default = false
}

variable "enable_vpc_changes" {
  type    = bool
  default = false
}

variable "enable_network_gw_changes" {
  type    = bool
  default = false
}

variable "enable_org_changes" {
  type    = bool
  default = false
}

variable "enable_no_mfa_login" {
  type    = bool
  default = false
}

variable "enable_login_failures" {
  type    = bool
  default = false
}

variable "enable_diable_or_delete_CMK" {
  type    = bool
  default = false
}

variable "enable_nacl_changes" {
  type    = bool
  default = false
}
