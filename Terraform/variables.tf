variable "resource_group_name" {
  description = "Nom du groupe de ressources Azure"
  type        = string
  default     = "rg-soc-lab"
}

variable "location" {
  description = "Région Azure"
  type        = string
  default     = "westeurope"
}

variable "admin_username" {
  description = "Utilisateur admin de la VM"
  type        = string
  default     = "socadmin"
}

variable "vm_size" {
  description = "Taille de la VM (16 Go RAM requis pour la stack SOC)"
  type        = string
  default     = "Standard_D4s_v3" # 4 vCPU, 16 Go RAM
}

variable "disk_size_gb" {
  description = "Taille du disque OS en Go"
  type        = number
  default     = 256
}