output "user_arn" {
  value = aws_iam_user.user.*.arn
}

output "access_key_id" {
  value = aws_iam_access_key.newemp.*.id
}

output "access_key_secret" {
  value     = aws_iam_access_key.newemp.*.encrypted_secret
  sensitive = true
}

output "bastion_public_ip" {
  value = aws_instance.public-ec2-instance.*.public_ip
}

output "mysql_endpoint" {
  value = aws_db_instance.default.endpoint
}
# output "private_instance_ip" {
#   value = aws_instance.private-ec2-instance.*.private_ip
# }
