variable "vpc_cidr" {
  default = "10.0.0.0/16"
}
variable "environment" {
  default = "dev"
}
variable "public_subnets_cidr" {
  type    = list(any)
  default = ["10.0.101.0/24", "10.0.102.0/24"]
}
variable "private_subnets_cidr" {
  type    = list(any)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "region" {
  default = "us-east-1"
}
variable "az" {
  type    = list(any)
  default = ["us-east-1a", "us-east-1b"]
}

variable "ami" {
#  default = "ami-087c17d1fe0178315"
  default = "ami-003cc785678c54dc1"
}
variable "instance-type" {
  default = "t2.micro"
}
variable "key-name" {
  default = "ec2-keypair"
}
variable "nonadmin_user" {
  type    = list(any)
  default = ["Arun", "Sumit"]
}
variable "admin_user" {
  type    = list(any)
  default = ["Modi"]
}
variable "username" {
  type    = list(any)
  default = ["Arun", "Sumit", "Modi"]
}
variable "dbversion" {
  default = "8.0.28"
}
variable "dbname" {
  default = "mysql001"
}
variable "dbusername" {
  default = "admin"
}
variable "dbpassword" {
  default = "admin123"
}

variable "domain" {
  type    = string
  default = "sampleapp.ml"
}
# variable "dbsg" {
#   type = set(string)
#   default = [ "dev" ]

# }

variable "zoneid" {
  default = "Z003578825BINPCJEGXBO"

}

variable "emailid" {
  type = string
  default = "arun.j@goballogic.com"
  
}
