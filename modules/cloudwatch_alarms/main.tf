// BEST PRACTICES ALARMS //
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  count               = var.enable_root_usage ? 1 : 0
  alarm_name          = "${var.account_name}-RootUsage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "RootUsage"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Root account usage has been detected"
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  count               = var.enable_security_group_changes ? 1 : 0
  alarm_name          = "${var.account_name}-SecurityGroupChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "SecurityGroupChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Security group changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg_changes" {
  count               = var.enable_cloudtrail_cfg_changes ? 1 : 0
  alarm_name          = "${var.account_name}-CloudTrailCfgChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "CloudTrailCfgChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "CloudTrail configuration changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  count               = var.enable_iam_changes ? 1 : 0
  alarm_name          = "${var.account_name}-IamChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "IamChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "IAM changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_call" {
  count               = var.enable_unauthorized_api_call ? 1 : 0
  alarm_name          = "${var.account_name}-UnauthorizedAPICalls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1000"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "UnauthorizedAPICalls"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Unauthorized API calls have been detected"
}

resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  count               = var.enable_aws_config_changes ? 1 : 0
  alarm_name          = "${var.account_name}-AwsConfigChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "AwsConfigChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "AWS Config changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "bucket_policy_changes" {
  count               = var.enable_bucket_policy_changes ? 1 : 0
  alarm_name          = "${var.account_name}-S3BucketPolicyChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "S3BucketPolicyChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "S3 bucket policy changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  count               = var.enable_route_table_changes ? 1 : 0
  alarm_name          = "${var.account_name}-RouteTableChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "RouteTableChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Route table changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  count               = var.enable_vpc_changes ? 1 : 0
  alarm_name          = "${var.account_name}-VpcChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "VpcChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "VPC changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "network_gw_changes" {
  count               = var.enable_network_gw_changes ? 1 : 0
  alarm_name          = "${var.account_name}-NetworkGWChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "NetworkGWChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Network gateway changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "org_changes" {
  count               = var.enable_org_changes ? 1 : 0
  alarm_name          = "${var.account_name}-OrgChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "OrgChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Organization changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "no_mfa_login" {
  count               = var.enable_no_mfa_login ? 1 : 0
  alarm_name          = "${var.account_name}-NoMFAConsoleSignin"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "NoMFAConsoleSignin"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Console signin without MFA has been detected"
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  count               = var.enable_nacl_changes ? 1 : 0
  alarm_name          = "${var.account_name}-NaclChanges"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "1"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "NaclChanges"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Network ACL changes have been detected"
}

resource "aws_cloudwatch_metric_alarm" "login_failures" {
  count               = var.enable_login_failures ? 1 : 0
  alarm_name          = "${var.account_name}-ConsoleSigninFailures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "15"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "ConsoleSigninFailures"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Console signin failures have exceeded the threshold"
}

resource "aws_cloudwatch_metric_alarm" "diable_or_delete_CMK" {
  count               = var.enable_diable_or_delete_CMK ? 1 : 0
  alarm_name          = "${var.account_name}-DisableOrDeleteCMK"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  threshold           = "15"
  period              = "3600"
  statistic           = "Sum"
  namespace           = var.namespace
  metric_name         = "DisableOrDeleteCMK"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.opsgenie_sns_topic]
  ok_actions          = [var.opsgenie_sns_topic]
  alarm_description   = "Customer master key is disabled or scheduled for deletion"
}

// METRIC FILTERS //
resource "aws_cloudwatch_log_metric_filter" "AwsConfigChanges" {
  count          = var.enable_aws_config_changes ? 1 : 0
  name           = "AwsConfigChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "AwsConfigChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "CloudTrailCfgChanges" {
  count          = var.enable_cloudtrail_cfg_changes ? 1 : 0
  name           = "CloudTrailCfgChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "CloudTrailCfgChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "ConsoleSigninFailures" {
  count          = var.enable_login_failures ? 1 : 0
  name           = "ConsoleSigninFailures"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "ConsoleSigninFailures"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "DisableOrDeleteCMK" {
  count          = var.enable_diable_or_delete_CMK ? 1 : 0
  name           = "DisableOrDeleteCMK"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "DisableOrDeleteCMK"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "IamChanges" {
  count          = var.enable_iam_changes ? 1 : 0
  name           = "IamChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "IamChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "NaclChanges" {
  count          = var.enable_nacl_changes ? 1 : 0
  name           = "NaclChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "NaclChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "NetworkGWChanges" {
  count          = var.enable_network_gw_changes ? 1 : 0
  name           = "NetworkGWChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "NetworkGWChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "NoMFAConsoleSignin" {
  count          = var.enable_no_mfa_login ? 1 : 0
  name           = "NoMFAConsoleSignin"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "NoMFAConsoleSignin"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "OrgChanges" {
  count          = var.enable_org_changes ? 1 : 0
  name           = "OrgChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "OrgChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName= "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName ="UpdateOrganizationalUnit")) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "RootUsage" {
  count          = var.enable_root_usage ? 1 : 0
  name           = "RootUsage"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "RootUsage"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "RouteTableChanges" {
  count          = var.enable_route_table_changes ? 1 : 0
  name           = "RouteTableChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "RouteTableChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "S3BucketPolicyChanges" {
  count          = var.enable_bucket_policy_changes ? 1 : 0
  name           = "S3BucketPolicyChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "S3BucketPolicyChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "SecurityGroupChanges" {
  count          = var.enable_security_group_changes ? 1 : 0
  name           = "SecurityGroupChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "SecurityGroupChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "UnauthorizedAPICalls" {
  count          = var.enable_unauthorized_api_call ? 1 : 0
  name           = "UnauthorizedAPICalls"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "UnauthorizedAPICalls"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  {(($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")) && (($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket"))}
  EOT
}

resource "aws_cloudwatch_log_metric_filter" "VpcChanges" {
  count          = var.enable_vpc_changes ? 1 : 0
  name           = "VpcChanges"
  log_group_name = var.log_group_name
  metric_transformation {
    name          = "VpcChanges"
    namespace     = var.namespace
    value         = "1"
    default_value = "0"
  }
  pattern = <<EOT
  { ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }
  EOT
}
