output "public_ip" {
  description = "IP publique de la VM SOC"
  value       = azurerm_public_ip.soc_pip.ip_address
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.soc_vm.name
}

output "ssh_command" {
  value = "ssh ${var.admin_username}@${azurerm_public_ip.soc_pip.ip_address}"
}