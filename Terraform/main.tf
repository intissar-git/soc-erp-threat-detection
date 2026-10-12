terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "soc_rg" {
  name     = var.resource_group_name
  location = var.location
}

# Réseau virtuel
resource "azurerm_virtual_network" "soc_vnet" {
  name                = "vnet-soc"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.soc_rg.location
  resource_group_name = azurerm_resource_group.soc_rg.name
}

resource "azurerm_subnet" "soc_subnet" {
  name                 = "snet-soc"
  resource_group_name  = azurerm_resource_group.soc_rg.name
  virtual_network_name = azurerm_virtual_network.soc_vnet.name
  address_prefixes     = ["10.10.1.0/24"]
}

# IP publique
resource "azurerm_public_ip" "soc_pip" {
  name                = "pip-soc"
  location            = azurerm_resource_group.soc_rg.location
  resource_group_name = azurerm_resource_group.soc_rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

# Network Security Group (pare-feu cloud)
resource "azurerm_network_security_group" "soc_nsg" {
  name                = "nsg-soc"
  location            = azurerm_resource_group.soc_rg.location
  resource_group_name = azurerm_resource_group.soc_rg.name

  # SSH (à restreindre en production)
  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Wazuh agent enrollment
  security_rule {
    name                       = "allow-wazuh-agent"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1514-1515"
    source_address_prefix      = "10.10.0.0/16"
    destination_address_prefix = "*"
  }

  # Wazuh dashboard
  security_rule {
    name                       = "allow-wazuh-dashboard"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # OpenSearch / Wazuh indexer
  security_rule {
    name                       = "allow-opensearch"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "9200"
    source_address_prefix      = "10.10.0.0/16"
    destination_address_prefix = "*"
  }

  # Shuffle SOAR
  security_rule {
    name                       = "allow-shuffle"
    priority                   = 140
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3001"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Interface réseau
resource "azurerm_network_interface" "soc_nic" {
  name                = "nic-soc"
  location            = azurerm_resource_group.soc_rg.location
  resource_group_name = azurerm_resource_group.soc_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.soc_subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.soc_pip.id
  }
}

resource "azurerm_network_interface_security_group_association" "soc_nic_nsg" {
  network_interface_id      = azurerm_network_interface.soc_nic.id
  network_security_group_id = azurerm_network_security_group.soc_nsg.id
}

# VM SOC
resource "azurerm_linux_virtual_machine" "soc_vm" {
  name                = "vm-soc-lab"
  resource_group_name = azurerm_resource_group.soc_rg.name
  location            = azurerm_resource_group.soc_rg.location
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [azurerm_network_interface.soc_nic.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = filebase64("${path.module}/cloud-init.yaml")
}