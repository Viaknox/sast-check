# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "no_owner" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "no_owner_two_filters" {
  most_recent = true

  filter {
    name   = "name"
    values = ["my-app-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "name_regex_only" {
  name_regex  = "^app-"
  most_recent = true
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "with_owners" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "self_owned" {
  most_recent = true
  owners      = ["self"]
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_id_filter" {
  most_recent = true

  filter {
    name   = "owner-id"
    values = ["123456789012"]
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_alias_filter" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "not_most_recent" {
  filter {
    name   = "image-id"
    values = ["ami-0123456789abcdef0"]
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_availability_zones" "available" {
  state = "available"
}
