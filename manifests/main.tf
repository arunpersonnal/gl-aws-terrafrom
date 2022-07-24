#VPC
resource "aws_vpc" "vpc" {
  cidr_block       = var.vpc_cidr
  instance_tenancy = "default"

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

#SUBNET
resource "aws_subnet" "public-subnet" {
  count                   = length(var.public_subnets_cidr)
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.public_subnets_cidr[count.index]
  availability_zone       = var.az[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.environment}-${var.az[count.index]}-public-subnet"
    Environment = var.environment
  }
}

resource "aws_subnet" "private-subnet" {
  count                   = 2
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = var.private_subnets_cidr[count.index]
  availability_zone       = var.az[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name        = "${var.environment}-${var.az[count.index]}-private-subnet"
    Environment = var.environment
  }
}
#IGW
resource "aws_internet_gateway" "ig" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = "${var.environment}-igw"
    Environment = var.environment
  }
}

#EIP
resource "aws_eip" "eip" {
  vpc        = true
  depends_on = [aws_internet_gateway.ig]
}

#NAT_GW
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.public-subnet[0].id

  tags = {
    Name        = "${var.environment}-nat-gw"
    Environment = var.environment
  }
  depends_on = [aws_internet_gateway.ig]
}


#PUBLIC_ROUTE_TABLE
resource "aws_route_table" "pub-sub-rt" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name        = "${var.environment}-public-route-table"
    Environment = var.environment
  }
}

# #PRIVATE_ROUTE_TABLE
resource "aws_route_table" "pri-sub-rt" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name        = "${var.environment}-private-route-table"
    Environment = var.environment
  }
}

#PUBLIC_ROUTE
resource "aws_route" "pub-ig-rt" {
  route_table_id         = aws_route_table.pub-sub-rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.ig.id
}

#PRIVATE_ROUTE
resource "aws_route" "pri-nat-rt" {
  route_table_id         = aws_route_table.pri-sub-rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_nat_gateway.nat.id
}

#ASSOCIATE_PUBLICROUTE_TO_SUBNET
resource "aws_route_table_association" "pub-sub-rt-ass" {
  count          = length(var.public_subnets_cidr)
  subnet_id      = element(aws_subnet.public-subnet.*.id, count.index)
  route_table_id = aws_route_table.pub-sub-rt.id
}

resource "aws_route_table_association" "pri-sub-rt-ass" {
  count          = length(var.private_subnets_cidr)
  subnet_id      = element(aws_subnet.private-subnet.*.id, count.index)
  route_table_id = aws_route_table.pri-sub-rt.id
}

#SG
resource "aws_security_group" "sg" {
  vpc_id = aws_vpc.vpc.id
  # Inbound Rules
  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  # HTTPS access from anywhere
  # SSH access from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  # Outbound Rules
  # Internet access to anywhere
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-sg"
    Environment = var.environment
  }
}

#public_to_private_sg

resource "aws_security_group" "public-private-sg" {
  vpc_id = aws_vpc.vpc.id
  # Inbound Rules
  # HTTP access from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${aws_instance.public-ec2-instance.0.private_ip}/32", "${aws_instance.public-ec2-instance.1.private_ip}/32"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.lb-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-pub-private-sg"
    Environment = var.environment
  }

}
#
# resource "aws_instance" "private-ec2-instance" {
#   count                       = length(var.private_subnets_cidr)
#   ami                         = var.ami
#   instance_type               = var.instance-type
#   subnet_id                   = aws_subnet.private-subnet[count.index].id
#   vpc_security_group_ids      = [aws_security_group.public-private-sg.id]
#   key_name                    = aws_key_pair.tf-keypair.key_name
#   associate_public_ip_address = false

#   tags = {
#     Name = "${var.environment}-private-ec2-instance"
#   }
# }

resource "aws_instance" "public-ec2-instance" {
  count                  = length(var.public_subnets_cidr)
  ami                    = var.ami
  instance_type          = var.instance-type
  subnet_id              = aws_subnet.public-subnet[count.index].id
  vpc_security_group_ids = [aws_security_group.sg.id]
  key_name               = aws_key_pair.tf-keypair.key_name
  tags = {
    Name = "${var.environment}-public-ec2-instance"
  }
}
#RSAKEYPAIR
resource "aws_key_pair" "tf-keypair" {
  key_name   = var.key-name
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
#DownloadPEM
resource "local_file" "tfkey" {
  content  = tls_private_key.rsa.private_key_pem
  filename = "tfkey"
}

#IAMUSER
resource "aws_iam_user" "user" {
  count         = length(var.username)
  name          = element(var.username, count.index)
  path          = "/system/"
  force_destroy = true
}

#PROGRAMMATIC_ACCESS
resource "aws_iam_access_key" "newemp" {
  count = length(var.username)
  user  = element(var.username, count.index)

  depends_on = [aws_iam_user.user]
}

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = false
  allow_users_to_change_password = true
}

#NonAdminPolicy
resource "aws_iam_user_policy" "non_admin_user" {
  count = length(var.nonadmin_user)
  name  = "new"
  user  = element(var.nonadmin_user, count.index)
  depends_on = [
    aws_iam_user.user
  ]
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

#AdminPolicy
resource "aws_iam_user_policy" "admin_user" {
  count = length(var.admin_user)
  name  = "new"
  user  = element(var.admin_user, count.index)
  depends_on = [
    aws_iam_user.user
  ]
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}



# #AWSLAUNCHCONFIG
resource "aws_launch_configuration" "launch-config" {
  name                        = "${var.environment}-asg-launch-config"
  image_id                    = var.ami
  instance_type               = "t2.micro"
  key_name                    = aws_key_pair.tf-keypair.key_name
  security_groups             = [aws_security_group.public-private-sg.id]
  #associate_public_ip_address = "false"

  lifecycle {
    create_before_destroy = true
  }
}


# resource "aws_launch_template" "launch-template" {
#   name_prefix   = "autoscale"
#   image_id      = var.ami
#   instance_type = "t2.micro"
#   key_name      = aws_key_pair.tf-keypair.key_name
#   user_data = base64encode(file("script.sh"))
  
#   network_interfaces {
#     associate_public_ip_address = false
#     security_groups = [aws_security_group.public-private-sg.id]
#     subnet_id = []
#   }

#   lifecycle { 
#     create_before_destroy = true
#   }
# }
#AUTOSCALING_GROUP
resource "aws_autoscaling_group" "autoscaling_group" {
  name             = "${var.environment}-asg"
  max_size         = 4
  min_size         = 2
  desired_capacity = 2
  health_check_grace_period = 60
  vpc_zone_identifier = [for pri-sub in aws_subnet.private-subnet : pri-sub.id]
  target_group_arns = [aws_lb_target_group.alb-target.arn]
  launch_configuration      = aws_launch_configuration.launch-config.id

  tags = [
    {
      key                 = "Name"
      value               = "${var.environment}-autoscaled-instance"
      propagate_at_launch = true
    },
  ]

  # launch_template {
  #   id      = aws_launch_configuration.launch-config.id
  #   version = "$Latest"
  # }
}

#DBSUBNETGROUP
resource "aws_db_subnet_group" "db-subnet" {
  name       = "${var.environment}-dbsubnet"
  subnet_ids = [for pri-sub in aws_subnet.private-subnet : pri-sub.id]
}

#DB_SECURITY_GROUP
resource "aws_security_group" "pubsub-db" {
  name   = "${var.environment}-dbsg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = var.private_subnets_cidr
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


#RDS_MYSQL
resource "aws_db_instance" "default" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = var.dbversion
  instance_class         = "db.t3.micro"
  name                   = var.dbname
  username               = var.dbusername
  password               = var.dbpassword
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  db_subnet_group_name   = aws_db_subnet_group.db-subnet.name
  vpc_security_group_ids = [aws_security_group.pubsub-db.id]
}


#ACM + ROUTE53 RECORDS
data "aws_route53_zone" "main" {
  name         = var.domain
  private_zone = false
}

resource "aws_acm_certificate" "acm-certs" {
  domain_name               = var.domain
  subject_alternative_names = ["${var.environment}.${var.domain}"]
  validation_method         = "DNS"
}

resource "aws_route53_record" "domainrecord" {
  for_each = {
    for dvo in aws_acm_certificate.acm-certs.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.id
}


resource "aws_acm_certificate_validation" "acm-certs-validation" {
  timeouts {
    create = "5m"
  }
  certificate_arn         = aws_acm_certificate.acm-certs.arn
  validation_record_fqdns = [for record in aws_route53_record.domainrecord : record.fqdn]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "web-route53-record" {
  zone_id = data.aws_route53_zone.main.id
  name    = "${var.environment}.${var.domain}"
  type    = "CNAME"
  ttl     = 60
  records = [aws_lb.alb.dns_name]
}

#ALB
resource "aws_security_group" "lb-sg" {
  vpc_id = aws_vpc.vpc.id
  # Inbound Rules
  # HTTP access from anywhere

  # HTTPS access from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.environment}-lb-sg"
    Environment = var.environment
  }
}


resource "aws_lb_target_group" "alb-target" {
  name        = "${var.environment}-alb-target"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc.id

  health_check {
    healthy_threshold   = 5
    interval            = 10
    path                = "/"
    protocol            = "HTTP"
    unhealthy_threshold = 5
  }
}

# resource "aws_lb_target_group_attachment" "alb-target-group-attachment1" {
#   target_group_arn = aws_lb_target_group.alb-target.arn
#   target_id        = aws_instance.private-ec2-instance[0].id
#   port             = 80
# }

# resource "aws_lb_target_group_attachment" "alb-target-group-attachment2" {
#   target_group_arn = aws_lb_target_group.alb-target.arn
#   target_id        = aws_instance.private-ec2-instance[1].id
#   port             = 80
# }

#ALB
resource "aws_lb" "alb" {
  name               = "${var.environment}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb-sg.id]
  subnets            = [for subnet in aws_subnet.public-subnet : subnet.id]

  enable_deletion_protection = false

  tags = {
    Environment = var.environment
  }
}

#LB_LISTERNER
resource "aws_lb_listener" "alb-listener" {
  load_balancer_arn = aws_lb.alb.arn

  port            = 443
  protocol        = "HTTPS"
  ssl_policy      = "ELBSecurityPolicy-2016-08"
  certificate_arn = aws_acm_certificate_validation.acm-certs-validation.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb-target.arn

  }
}
#Autoscaling Target Attachments
resource "aws_autoscaling_attachment" "target-autoscaling" {
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
  alb_target_group_arn   = aws_lb_target_group.alb-target.arn
}

#Autoscaling Policy scale UP
resource "aws_autoscaling_policy" "scale-up-cpu-policy" {
  name                   = "${var.environment}-cpu-policy-scale-up"
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = "1"
 
 
  # cooldown: no utilization can happen!!!
  cooldown               = "300"
 
  policy_type            = "SimpleScaling"
}
#Autoscaling Policy scale Down
resource "aws_autoscaling_policy" "scale-down-cpu-policy" {
  name                   = "${var.environment}-cpu-policy-scale-down"
  autoscaling_group_name = aws_autoscaling_group.autoscaling_group.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = "-1"
 
  # cooldown: no utilization can happen!!!
  cooldown               = "300"
 
  policy_type            = "SimpleScaling"
}

#ScaleUPMetrics
resource "aws_cloudwatch_metric_alarm" "scale-up-cpu-alarm" {
  alarm_name          = "${var.environment}-cpu-scale-up-alarm"
  alarm_description   = "scale-up-cpu-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "90"
 
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.autoscaling_group.name
  }
 
  actions_enabled = true
  alarm_actions   = [aws_autoscaling_policy.scale-up-cpu-policy.arn]
}

#SCALEDOWNMETRICS
resource "aws_cloudwatch_metric_alarm" "scale-down-cpu-alarm" {
  alarm_name          = "${var.environment}-cpu-scale-down-alarm"
  alarm_description   = "scale-down-cpu-alarm"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "60"
  statistic           = "Average"
  threshold           = "30"
 
  dimensions = {
    "AutoScalingGroupName" = aws_autoscaling_group.autoscaling_group.name
  }
 
  actions_enabled = true
  alarm_actions   = [aws_autoscaling_policy.scale-down-cpu-policy.arn]
}

#SNS_NOTIFICATION
resource "aws_autoscaling_notification" "webserver_asg_notifications" {
  group_names = [
    aws_autoscaling_group.autoscaling_group.name
  ]

  notifications = [
    "autoscaling:EC2_INSTANCE_LAUNCH",
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
    "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
  ]

  topic_arn = aws_sns_topic.webserver_sns_topic.arn
}

#SNSTOPICS
resource "aws_sns_topic" "webserver_sns_topic" {
  name = "webserver_topic"
}

resource "aws_sns_topic_subscription" "email-target" {
  topic_arn = aws_sns_topic.webserver_sns_topic.arn
  protocol  = "email"
  endpoint  = var.emailid
}

#CloudTrail
data "aws_caller_identity" "current" {}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name = "${var.environment}-cloudtrail-cloudwatch_log_group"

  tags = {
    Name        = "${var.environment}-cloudtrail-cloudwatch_log_group"
    Environment = var.environment
  }
}

resource "aws_cloudtrail" "s3-cloudtrail" {
  name                          = "${var.environment}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.s3-cloudtrail.id
  s3_key_prefix                 = "terra"
  include_global_service_events = true
  sns_topic_name = aws_sns_topic.webserver_sns_topic.display_name
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail.arn
  tags = {
    Name        = "${var.environment}-cloudtrail"
    Environment = var.environment
  }

  depends_on = [aws_s3_bucket.s3-cloudtrail]
}

resource "aws_s3_bucket" "s3-cloudtrail" {
  bucket        = "${var.environment}-tf-cloudtrail"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "s3-cloudtrail" {
  bucket = aws_s3_bucket.s3-cloudtrail.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.s3-cloudtrail.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.s3-cloudtrail.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}
resource "aws_iam_role" "cloudtrail" {
  name = "${var.environment}-cloudTrail-cloudWatch-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "aws_iam_role_policy_cloudTrail_cloudWatch" {
  name = "${var.environment}-cloudTrail-cloudWatch-policy"
  role = aws_iam_role.cloudtrail.id

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailCreateLogStream2014110",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream"
            ],
            "Resource": [
                "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
            ]
        },
        {
            "Sid": "AWSCloudTrailPutLogEvents20141101",
            "Effect": "Allow",
            "Action": [
                "logs:PutLogEvents"
            ],
            "Resource": [
                "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
            ]
        }
    ]
}
EOF
}