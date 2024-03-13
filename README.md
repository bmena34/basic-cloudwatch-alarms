# Basic CloudWatch Alarms Module

This Terraform module creates basic CloudWatch alarms for monitoring your AWS resources.

## Features

- Creates CloudWatch alarms and Metric Filters for various AWS resources
- Custom metrics are place in user declared Namespace
- Easy to use and configure
- Allows separate .tf files per account, allowing user to pick and choose relevant alarms
- Built around OpsGenie SNS integration for alerting but `alarm_actions` and `ok_actions` can be modified.

## Requirements

- CloudWatch Log Group has been setup
- OpsGenie SNS integration has been setup

## Example Usage

```
module "prd_cloudwatch_alarms" {
  source = "./modules/cloudwatch_alarms"

  account_name       = "prd"
  namespace          = "Atomic/Security"
  opsgenie_sns_topic = data.aws_sns_topic.opsgenie.arn
  log_group_name     = data.aws_cloudwatch_log_group.security_agg.name

  enable_root_usage             = true
  enable_security_group_changes = true
  enable_cloudtrail_cfg_changes = true
  enable_iam_changes            = true
  enable_unauthorized_api_call  = true
  enable_aws_config_changes     = true
  enable_bucket_policy_changes  = true
  enable_route_table_changes    = true
  enable_vpc_changes            = true
  enable_network_gw_changes     = true
  enable_org_changes            = true
  enable_no_mfa_login           = true
  enable_login_failures         = true
  enable_diable_or_delete_CMK   = true
  enable_nacl_changes           = true

}

data "aws_sns_topic" "opsgenie" {
  name = "alerts-opsgenie"
}

data "aws_cloudwatch_log_group" "org_agg" {
  name = "/aws/cloudtrail/org-agg"
}
```
