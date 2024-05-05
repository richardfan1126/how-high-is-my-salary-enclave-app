data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

resource "aws_instance" "enclave_instance" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "c5.xlarge"
  subnet_id     = module.vpc.public_subnets[0]

  vpc_security_group_ids = [
    aws_security_group.instance_sg.id
  ]

  user_data = base64encode(templatefile("${path.module}/user-data.sh.tpl", {
    eifArtifactPath = var.eif_artifact_path
  }))

  enclave_options {
    enabled = true
  }

  tags = {
    Name = var.project_name
  }

  lifecycle {
    ignore_changes = [
      ami
    ]
  }
}
