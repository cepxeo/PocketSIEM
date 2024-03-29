output "aws_instance_public" {
  value = [ 
    "aws_instance_public_dns ${aws_instance.pocketsiem.public_dns}",
    "aws_instance_public_IP ${aws_instance.pocketsiem.public_ip}"
  ]
}

resource "local_file" "private_key" {
  content         = tls_private_key.arm_ssh_key.private_key_pem
  filename        = "pocketsiem-key.pem"
}