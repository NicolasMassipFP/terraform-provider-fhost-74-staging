package provider

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-log/tflogtest"
	"github.com/terraform-providers/terraform-provider-smc/internal/apijson"
)

func TestGetElementId(t *testing.T) {
	var config_data_json = `{
    "name": "mycluster",
    "nodes": [
        {
            "firewall_node": {
                "name": "mycluster node 1",
                "nodeid": 1
            }
        },
        {
            "firewall_node": {
                "name": "mycluster node 2",
                "nodeid": 2
            }
        }
    ]
}`

	var configData SingleFirewallResourceModel

	if err := apijson.UnmarshalRoot([]byte(config_data_json), &configData); err != nil {
		t.Fatalf("Failed to unmarshal createdData: %v", err)
	}

	fwnode0 := *(*configData.Nodes)[1].FirewallNode
	elementId, err := GetElementId(reflect.ValueOf(fwnode0))
	if err != nil {
		t.Fatalf("GetElementId failed: %v", err)
	}
	if elementId != "Nodeid/2" {
		t.Errorf("Expected elementId to be 'mycluster node Nodeid/2', got '%s'", elementId)
	}

	node0 := (*configData.Nodes)[1]
	elementId, err = GetElementId(reflect.ValueOf(node0))
	if err != nil {
		t.Fatalf("GetElementId failed: %v", err)
	}
	if elementId != "FirewallNode/Nodeid/2" {
		t.Errorf("Expected elementId to be 'mycluster node Nodeid/2', got '%s'", elementId)
	}
}

// Integration test using real provider models similar to main.go
func TestMergeHost(t *testing.T) {
	var config_data_json = `{
		"address": "192.168.1.2",
		"admin_domain": "http://localhost:8082/7.3/elements/admin_domain/1",
		"comment": "Created via Terraform",
		"key": 5253,
		"link": [
			{
				"href": "http://localhost:8082/7.3/elements/host/5253",
				"rel": "self",
				"type": "host"
			}
		],
		"name": "AExampleHost",
		"secondary": [
			"212.20.1.1",
			"123.6.5.19"
		]
	}`

	var created_data_json = `{
		"address": "192.168.1.2",
		"admin_domain": "xxxx",
		"comment": "Created via Terraform",
		"name": "AExampleHost",
		"secondary": ["212.20.1.1", "123.6.5.19"]
	}`

	var data HostResourceModel
	var createdData HostResourceModel
	ctx := tflogtest.RootLogger(context.Background(), os.Stdout)

	if err := apijson.UnmarshalRoot([]byte(config_data_json), &createdData); err != nil {
		t.Fatalf("Failed to unmarshal createdData: %v", err)
	}
	if err := apijson.UnmarshalRoot([]byte(created_data_json), &data); err != nil {
		t.Fatalf("Failed to unmarshal data: %v", err)
	}

	err := MergeResourceModels(ctx, &createdData, &data)
	if err != nil {
		t.Fatalf("MergeResourceModels failed: %v", err)
	}

	fmt.Printf("After merge, data: %+v\n", data)
	// Verify the merge worked - should have link data from createdData

	// verify the "lk"
	if data.Lk.IsNull() || data.Lk.IsUnknown() {
		t.Errorf("Expected Lk to be set after merge, but it is null or unknown")
	}
	selfLink := data.Lk.Elements()["self"].(types.String).ValueString()
	if selfLink != "http://localhost:8082/7.3/elements/host/5253" {
		t.Errorf("Expected Lk.Elements['self'] to be 'http://localhost:8082/7.3/elements/host/5253', got '%s'", selfLink)
	}
}

func TestMergeCluster(t *testing.T) {
	var config_data_json = `{
    "name": "mycluster",
    "nodes": [
        {
            "firewall_node": {
                "name": "mycluster node 1",
                "nodeid": 1
            }
        },
        {
            "firewall_node": {
                "name": "mycluster node 2",
                "nodeid": 2
            }
        }
    ]
}`

	var created_data_json = `{
    "name": "mycluster",
    "nodes":     [
        {
            "firewall_node": {
                "disabled": false,
                "key": 5387,
                "link": [
                    {
                        "href": "http://localhost:8082/7.3/elements/fw_cluster/5385/firewall_node/5387",
                        "rel": "self",
                        "type": "firewall_node"
                    },
                ],
                "name": "mycluster node 2",
                "nodeid": 2,
            }
        },
        {
            "firewall_node": {
                "activate_test": false,
                "appliance_info": {
                    "first_upload_time": 0,
                    "initial_contact_time": 0,
                    "initial_license_remaining_days": 0
                },
                "disabled": false,
                "key": 5386,
                "link": [
                    {
                        "href": "http://localhost:8082/7.3/elements/fw_cluster/5385/firewall_node/5386",
                        "rel": "self",
                        "type": "firewall_node"
                    }                ],
                "name": "mycluster node 1",
                "nodeid": 1,
            }
        },
    ]
}`

	var configData FirewallClusterResourceModel
	var createdData FirewallClusterResourceModel

	if err := apijson.UnmarshalRoot([]byte(config_data_json), &configData); err != nil {
		t.Fatalf("Failed to unmarshal createdData: %v", err)
	}
	if err := apijson.UnmarshalRoot([]byte(created_data_json), &createdData); err != nil {
		t.Fatalf("Failed to unmarshal configData: %v", err)
	}

	err := MergeResourceModels(context.TODO() /*src*/, &createdData /*dest*/, &configData)
	if err != nil {
		t.Fatalf("MergeResourceModels failed: %v", err)
	}

	fmt.Printf("After merge, configData: %+v\n", (*configData.Nodes)[0].FirewallNode)
	nodesLinks, _ := (*(*configData.Nodes)[0].FirewallNode).Link.AsStructSliceT(context.TODO())

	if nodesLinks[0].Href.ValueString() != "http://localhost:8082/7.3/elements/fw_cluster/5385/firewall_node/5386" {
		t.Errorf("Wrong Link Href after merge: %s", nodesLinks[0].Href.ValueString())
	}

}

func TestMergeSingleFw(t *testing.T) {
	var config_data_json = `{
    "log_server_ref": "http://localhost:8082/7.3/elements/log_server/1441",
    "name": "myfw",
    "nodes": [
        {
            "firewall_node": {
                "name": "myfwnode",
                "nodeid": 1
            }
        }
    ],
    "physicalInterfaces": [
        {
            "physical_interface": {
                "interface_id": "0",
                "interfaces": [
                    {
                        "single_node_interface": {
                            "address": "192.168.100.14",
                            "network_value": "192.168.100.00/24",
                            "nicid": "0",
                            "nodeid": 1,
                            "primary_mgt": true
                        }
                    }
                ]
            }
        },
        {
            "physical_interface": {
                "interface_id": "1",
                "interfaces": [
                    {
                        "single_node_interface": {
                            "address": "192.168.101.14",
                            "network_value": "192.168.101.00/24",
                            "nicid": "1",
                            "nodeid": 1
                        }
                    }
                ]
            }
        }
    ]
}`

	var created_data_json = `{
    "key": 5437,
    "log_server_ref": "http://localhost:8082/7.3/elements/log_server/1441",
    "name": "myfw",
    "physicalInterfaces": [
        {
            "physical_interface": {
                "aggregate_mode": "none",
                "arp_entry": [],
                "cvi_mode": "none",
                "dhcp_server_on_interface": {
                    "default_lease_time": 7200,
                    "dhcp_range_per_node": []
                },
                "duplicate_address_detection": true,
                "include_prefix_info_option_flag": true,
                "interface_id": "0",
                "interfaces": [
                    {
                        "single_node_interface": {
                            "address": "192.168.100.14",
                            "auth_request": false,
                            "auth_request_source": false,
                            "automatic_default_route": false,
                            "backup_heartbeat": false,
                            "backup_mgt": false,
                            "domain_specific_dns_queries_source": false,
                            "dynamic": false,
                            "key": 1343,
                            "network_value": "192.168.100.0/24",
                            "nicid": "0",
                            "nodeid": 1,
                            "outgoing": false,
                            "pppoa": false,
                            "pppoe": false,
                            "primary_heartbeat": false,
                            "primary_mgt": true,
                            "relayed_by_dhcp": false,
                            "reverse_connection": false,
                            "vrrp": false,
                            "vrrp_id": -1,
                            "vrrp_priority": -1
                        }
                    }
                ],
                "key": 727,
                "link": [
                    {
                        "href": "http://localhost:8082/7.3/elements/single_fw/5437/physical_interface/727",
                        "rel": "self",
                        "type": "physical_interface"
                    }
                ],
                "lldp_mode": "disabled",
                "log_moderation": [
                    {
                        "burst": 1000,
                        "log_event": "antispoofing",
                        "rate": 100
                    },
                    {
                        "burst": 20000,
                        "log_event": "discard",
                        "rate": 5000
                    },
                    {
                        "burst": 80000,
                        "log_event": "allow",
                        "rate": 40000
                    }
                ],
                "managed_address_flag": false,
                "mtu": -1,
                "name": "Interface 0",
                "other_configuration_flag": false,
                "override_engine_settings": false,
                "override_log_moderation_settings": false,
                "qos_limit": 0,
                "qos_mode": "no_qos",
                "route_replies_back_mode": false,
                "router_advertisement": false,
                "set_autonomous_address_flag": true,
                "shared_interface": false,
                "syn_mode": "default",
                "sync_parameter": {
                    "full_sync_interval": 5000,
                    "heartbeat_group_ip": "224.0.0.221",
                    "incr_sync_interval": 50,
                    "statesync_group_ip": "224.0.0.222",
                    "sync_mode": "sync_all",
                    "sync_security": "sign"
                },
                "virtual_engine_vlan_ok": false,
                "virtual_resource_settings": [],
                "vlanInterfaces": []
            }
        }
    ],
}`

	ctx := tflogtest.RootLogger(context.Background(), os.Stdout)
	tflog.Info(ctx, "test log message", map[string]interface{}{
		"key": "value",
	})

	var configData SingleFirewallResourceModel
	var createdData SingleFirewallResourceModel

	if err := apijson.UnmarshalRoot([]byte(config_data_json), &configData); err != nil {
		t.Fatalf("Failed to unmarshal createdData: %v", err)
	}
	if err := apijson.UnmarshalRoot([]byte(created_data_json), &createdData); err != nil {
		t.Fatalf("Failed to unmarshal configData: %v", err)
	}

	err := MergeResourceModels(ctx, &createdData, &configData)
	if err != nil {
		t.Fatalf("MergeResourceModels failed: %v", err)
	}

	expectedRootKey := int64(5437)
	actualRootKey := configData.Key.ValueInt64()
	if actualRootKey != expectedRootKey {
		t.Errorf("Expected root Key to be %d, got %d", expectedRootKey, actualRootKey)
	}

	physicalInterface0 := (*configData.PhysicalInterfaces)[0].PhysicalInterface
	expectedPhysInterfaceKey := int64(727)
	actualPhysInterfaceKey := physicalInterface0.Key.ValueInt64()
	if actualPhysInterfaceKey != expectedPhysInterfaceKey {
		t.Errorf("Expected PhysicalInterface Key to be %d, got %d", expectedPhysInterfaceKey, actualPhysInterfaceKey)
	}
	singleNodeInterface := (*physicalInterface0.Interfaces)[0].SingleNodeInterface
	expectedSingleNodeKey := int64(1343)
	actualSingleNodeKey := singleNodeInterface.Key.ValueInt64()
	if actualSingleNodeKey != expectedSingleNodeKey {
		t.Errorf("Expected SingleNodeInterface Key to be %d, got %d", expectedSingleNodeKey, actualSingleNodeKey)
	}
}

