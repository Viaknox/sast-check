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

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "empty_owners" {
  most_recent = true
  owners      = []
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "empty_owner_filter" {
  most_recent = true

  filter {
    name   = "owner-id"
    values = []
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

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_from_var" {
  most_recent = true
  owners      = var.ami_owners
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_from_local" {
  most_recent = true
  owners      = local.owners
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_from_module" {
  most_recent = true
  owners      = module.accounts.owners
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_filter_from_var" {
  most_recent = true

  filter {
    name   = "owner-id"
    values = var.owner_ids
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_filter_from_local" {
  most_recent = true

  filter {
    name   = "owner-id"
    values = local.owner_ids
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_filter_from_module" {
  most_recent = true

  filter {
    name   = "owner-id"
    values = module.accounts.owner_ids
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_alias_from_var" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = var.owner_aliases
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_alias_from_local" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = local.owner_aliases
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owner_alias_from_module" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = module.accounts.owner_aliases
  }
}

# owner given by a variable whose default, in this file, is an empty list: no restriction at all
variable "empty_owners_var" {
  type    = list(string)
  default = []
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_var_defaults_empty" {
  most_recent = true
  owners      = var.empty_owners_var
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_var_defined_later" {
  owners      = var.late_empty_owners
  most_recent = true

  filter {
    name   = "name"
    values = ["my-app-*"]
  }
}

variable "late_empty_owners" {
  description = "Account IDs allowed to own the image"
  type        = list(string)
  default     = []
}

locals {
  empty_local_owners = []
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_local_defaults_empty" {
  most_recent = true
  owners      = local.empty_local_owners
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_local_defined_later" {
  most_recent = true
  owners      = local.late_empty_local_owners
}

locals {
  late_empty_local_owners = []
}

variable "pinned_owners_var" {
  type    = list(string)
  default = ["099720109477"]
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_var_default_set" {
  most_recent = true
  owners      = var.pinned_owners_var
}

variable "required_owners_var" {
  type = list(string)
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_var_no_default" {
  most_recent = true
  owners      = var.required_owners_var
}

locals {
  pinned_local_owners = ["self"]
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "owners_local_set" {
  most_recent = true
  owners      = local.pinned_local_owners
}

variable "empty_but_unused" {
  type    = list(string)
  default = []
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "other_var_is_used" {
  most_recent = true
  owners      = var.pinned_owners_var
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "empty_default_but_not_most_recent" {
  owners = var.empty_but_unused

  filter {
    name   = "image-id"
    values = ["ami-0123456789abcdef0"]
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "empty_default_but_owner_filter_literal" {
  most_recent = true
  owners      = var.empty_but_unused

  filter {
    name   = "owner-id"
    values = ["123456789012"]
  }
}

# an empty default that a validation rejects can never reach the data source: the caller must supply owners
variable "validated_gt0_owners" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.validated_gt0_owners) > 0
    error_message = "Give at least one AMI owner."
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "validated_gt0_before" {
  most_recent = true
  owners      = var.validated_gt0_owners
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "validated_ge1_after" {
  most_recent = true
  owners      = var.validated_ge1_owners
}

variable "validated_ge1_owners" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.validated_ge1_owners) >= 1
    error_message = "Give at least one AMI owner."
  }
}

variable "validated_ne0_owners" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.validated_ne0_owners) != 0 && alltrue([for o in var.validated_ne0_owners : can(regex("^[0-9]{12}$", o))])
    error_message = "Give at least one 12-digit AMI owner."
  }
}

# ok: sast.terraform.aws-ami-no-owner
data "aws_ami" "validated_ne0_before" {
  most_recent = true
  owners      = var.validated_ne0_owners
}

variable "unrelated_validation_owners" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.unrelated_validation_owners) < 5
    error_message = "At most four owners."
  }
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "unrelated_validation_before" {
  most_recent = true
  owners      = var.unrelated_validation_owners
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "unrelated_validation_after" {
  most_recent = true
  owners      = var.unrelated_validation_late
}

variable "unrelated_validation_late" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.unrelated_validation_late) < 5
    error_message = "At most four owners."
  }
}

variable "or_validation_owners" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.or_validation_owners) > 0 || var.allow_empty
    error_message = "Give owners or allow empty."
  }
}

# ruleid: sast.terraform.aws-ami-no-owner
data "aws_ami" "or_validation_before" {
  most_recent = true
  owners      = var.or_validation_owners
}
