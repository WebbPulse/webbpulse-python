"""`wp-tf`: plan-only runs on the WebbPulse Terraform control plane from a workstation or an agent.

It tars a directory, starts a plan-only run on a workspace and streams the log, which is
what a remote `terraform plan` against HCP Terraform did. It reuses the `wpk_` key that
`terraform login <host>` leaves in `credentials.tfrc.json`, so there is no separate login,
and it never confirms or applies: a login key holds no `runs:apply` scope.

`webbpulse.tf.client` needs httpx, from the `tf` extra; the other modules need nothing.
"""
