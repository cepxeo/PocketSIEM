##################################################################################
# VARIABLES
##################################################################################

variable "region" {}
variable "domain" {}
variable "admin_ip" {}

##################################################################################
# PROVIDERS
##################################################################################

provider "aws" {
  region     = var.region
}

##################################################################################
# RESOURCES
##################################################################################

resource "aws_default_vpc" "default" {

}

resource "aws_security_group" "pocketsiem" {
  name        = "ubuntu"
  description = "Allow ports for ubuntu"
  vpc_id      = aws_default_vpc.default.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create an SSH key
resource "tls_private_key" "arm_ssh_key" {

  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "pocketsiem-key" {
  key_name   = "pocketsiem-key"
  public_key = "${tls_private_key.arm_ssh_key.public_key_openssh}"
}

resource "aws_instance" "pocketsiem" {
  ami                    = "ami-092391a11f8aa4b7b"
  instance_type          = "t2.micro"
  key_name      = "pocketsiem-key"
  vpc_security_group_ids = [aws_security_group.pocketsiem.id]

  connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ubuntu"
    private_key = "${tls_private_key.arm_ssh_key.private_key_pem}"
  }

  provisioner "remote-exec" {
  inline = [
    "sudo apt update && sudo apt -y upgrade",
    "sudo snap install certbot --classic",
    "sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release",
    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg",
    "echo \"deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null",
    "sudo apt-get update",
    "sudo apt-get install -y docker-ce docker-ce-cli containerd.io",
    "sudo usermod -aG docker $USER",
    "sudo curl -L \"https://github.com/docker/compose/releases/download/1.29.1/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose",
    "sudo chmod +x /usr/local/bin/docker-compose",
    "sudo certbot certonly --register-unsafely-without-email --agree-tos --standalone -d ${var.domain}",
    "git clone https://github.com/cepxeo/PocketSIEM",
    "cd PocketSIEM/Server",
    "sudo cp /etc/letsencrypt/live/${var.domain}/fullchain.pem cert.pem",
    "sudo cp /etc/letsencrypt/live/${var.domain}/privkey.pem key.pem",
    "sudo chown ubuntu *.pem",
    "sudo docker build -t pocketsiem:1 .",
    "sudo docker run -d --network host -p 443:443 pocketsiem:1"
  ]
  }
}