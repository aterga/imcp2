output "public_ip" {
  description = "Elastic IP of the instance."
  value       = aws_eip.mcp.public_ip
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.mcp.id
}

output "server_url" {
  description = "Where the MCP server is reachable once Caddy issues a cert (a minute or two after apply)."
  value       = "https://${local.domain}"
}

output "dns_note" {
  description = "Whether any DNS action is needed."
  value       = var.domain == "" ? "Using ${local.domain} (sslip.io) — no DNS setup needed." : "Create an A record: ${var.domain} -> ${aws_eip.mcp.public_ip}"
}

output "ssm_session_command" {
  description = "Shell into the box without SSH (requires the AWS CLI Session Manager plugin)."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.mcp.id}"
}
