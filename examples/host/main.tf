
resource "smc_host" "example" {
  name = "AExampleHost"
  address = "192.168.1.44"
  comment = "Created via Terraform"
  secondary = ["212.20.1.1", "123.6.5.22"]
}

output "host_href" {
  # you can access to the links of the host like this
  value = smc_host.example.lk.self
}
