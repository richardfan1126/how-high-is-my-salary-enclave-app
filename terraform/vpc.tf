module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = var.project_name
  cidr = "10.0.0.0/16"

  azs = [
    "us-east-1a"
  ]

  public_subnets = [
    "10.0.0.0/24"
  ]

  enable_nat_gateway            = false
  enable_vpn_gateway            = false
  manage_default_security_group = false
  map_public_ip_on_launch       = true
}

resource "aws_security_group" "instance_sg" {
  name   = var.project_name
  vpc_id = module.vpc.vpc_id

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  ingress {
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
}
