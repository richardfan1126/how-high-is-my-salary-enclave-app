output "instance_public_ip" {
  value = aws_instance.enclave_instance.public_ip
}
