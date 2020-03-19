use crate::er::{self, Result};
use crate::server;
use crate::utils::{self, CliEnv};
use rusoto_core::Region;
use rusoto_ec2::{
    AllocateAddressRequest, AssociateAddressRequest, AuthorizeSecurityGroupIngressRequest,
    CreateKeyPairRequest, CreateSecurityGroupRequest, DescribeAddressesRequest, Ec2, Ec2Client,
    IpPermission, IpRange, RunInstancesRequest,
};
use serde::{Deserialize, Serialize};
use std::io;

// Thought around this,
// security..
// could have multiple accounts,
// especially one to provision machines,
// another to configure/connect to machines
// possibly more
#[derive(Serialize, Deserialize, Clone)]
pub struct AwsConfig {
    pub key: String,
    pub secret: String,
}

fn get_config_file(env: &CliEnv) -> std::path::PathBuf {
    let mut config_file = env.config_dirs.config_root.clone();
    config_file.push("aws_credentials");
    config_file
}

pub fn get_config(env: &CliEnv) -> Result<AwsConfig> {
    let config_file = get_config_file(env);
    let json_file = std::fs::File::open(config_file)?;
    let buf_reader = io::BufReader::new(json_file);
    let config = serde_json::from_reader::<_, AwsConfig>(buf_reader)?;
    Ok(config)
}

pub fn aws_config(env: &CliEnv) -> Result<()> {
    let config_file = get_config_file(env);
    let current_config = if config_file.is_file() {
        Some(get_config(env)?)
    } else {
        None
    };
    match &current_config {
        Some(_current_config) => {
            println!("Config exists, modifying");
        }
        None => {
            println!("No current config, creating");
            println!("Expecting IAM user credentials with ec2 permissions");
        }
    }
    let key = env.get_input("Key", current_config.as_ref().map(|c| c.key.clone()))?;
    let secret = env.get_input("Secret", current_config.as_ref().map(|c| c.key.clone()))?;
    let config = AwsConfig { key, secret };
    let content_str = match serde_json::to_string_pretty(&config) {
        Ok(content_str) => content_str,
        Err(e) => return Err(er::SerdeJson::e(e).into()),
    };
    utils::ensure_parent_dir(&config_file)?;
    match std::fs::write(config_file, content_str) {
        Ok(_) => {
            println!("Wrote aws config");
            Ok(())
        }
        Err(e) => {
            eprintln!("Couldn't write aws config: {:?}", e);
            Err(e.into())
        }
    }
}

// Todo: Possibly os could be unix? How will it work for os x
#[cfg(target_os = "linux")]
fn set_pem_perms(pem_file: &std::path::Path) -> Result<()> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let permissions = Permissions::from_mode(0o400);
    std::fs::set_permissions(pem_file, permissions)?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn set_pem_perms(pem_file: &std::path::Path) -> Result<()> {
    use std::fs::Permissions;
    let metadata = pem_file.metadata()?;
    let mut permissions = metadata.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(pem_file, permissions)?;
    Ok(())
}

pub fn create_ec2_client(env: &CliEnv) -> Result<Ec2Client> {
    let aws_config = get_config(env)?;
    std::env::set_var("AWS_ACCESS_KEY_ID", aws_config.key);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", aws_config.secret);
    /*
    let credentials = rusoto_credential::AwsCredentials::new(
        aws_config.key,
        aws_config.secret,
        None,
        None
    );*/
    Ok(Ec2Client::new(Region::EuNorth1))
}

use server::ElasticIp;

// todo: Keep progress and allow to continue,
// also allow to teardown when interrupted as well as completed.
// Can first do a dry run to check permissions, then
// alert user of missing permission to increase chance
// of not aborted process
// todo: Clean up stack to run in case of failures,
// should be persisted
pub fn provision_server(env: &CliEnv, dry_run: bool) -> Result<()> {
    // todo: Allow "reprovision" of existing server
    let server_name = env.get_input("Server name", None)?;
    if crate::server::has_config(env, &server_name) {
        eprintln!("Server name already exist. \"Reprovision\" not implemented");
        return er::err("Server name already exist");
    }
    let ec2_client = create_ec2_client(&env)?;
    // Select or provision address
    // Can use this to get ip of specific instance with filter
    let desribe_addr = ec2_client
        .describe_addresses(DescribeAddressesRequest {
            allocation_ids: None,
            dry_run: Some(dry_run),
            filters: None,
            public_ips: None,
        })
        .sync()
        .map_err(er::Rusoto::e)?;
    // Allow to select from those not assigned
    let selected_addr = match desribe_addr.addresses {
        Some(addrs) => {
            let mut select_from = addrs
                .iter()
                .filter_map(|a| match (&a.instance_id, &a.allocation_id, &a.public_ip) {
                    (None, Some(allocation_id), Some(public_ip)) => Some(ElasticIp {
                        allocation_id: allocation_id.to_owned(),
                        public_ip: public_ip.to_owned(),
                    }),
                    _ => None,
                })
                .collect::<Vec<ElasticIp>>();
            if select_from.len() == 0 {
                None
            } else {
                match env.select_or_add(
                    "Select ip address",
                    &select_from
                        .iter()
                        .map(|ElasticIp { public_ip, .. }| public_ip)
                        .collect(),
                    None,
                )? {
                    utils::SelectOrAdd::Selected(idx) => Some(select_from.remove(idx)),
                    utils::SelectOrAdd::AddNew => None,
                }
            }
        }
        None => None,
    };
    // If none available, or add new selected, allocate new ip
    let addr = match selected_addr {
        Some(addr) => addr,
        None => {
            print!("Allocating address.. ");
            let result = ec2_client
                .allocate_address(AllocateAddressRequest {
                    address: None,
                    domain: None,
                    dry_run: Some(dry_run),
                    public_ipv_4_pool: None,
                })
                .sync()
                .map_err(er::Rusoto::e)?;
            println!("OK");
            match (result.allocation_id, result.public_ip) {
                (Some(allocation_id), Some(public_ip)) => ElasticIp {
                    allocation_id,
                    public_ip,
                },
                _ => return er::err("Could not extract allocation_id and public_ip from result"),
            }
        }
    };
    // Create key pair
    print!("Creating key pair.. ");
    let key_pair = ec2_client
        .create_key_pair(CreateKeyPairRequest {
            key_name: server_name.clone(),
            dry_run: Some(dry_run),
        })
        .sync()
        .map_err(er::Rusoto::e)?;
    println!("OK");
    // Write "material", .pem file
    // todo: Can we use "key_finterprint" for the private key?
    println!("key_fingerprint: {:?}", key_pair.key_fingerprint);
    let pem_file = format!("{}.pem", server_name);
    let pem_path = env
        .config_dirs
        .servers
        .filepath(&format!(".pem/{}", pem_file));
    match key_pair.key_material {
        Some(key_material) => utils::write_file(&pem_path, &key_material)?,
        None => return er::err("Failed to get key material (pem)"),
    }
    // Set permission to 400 or read only dependent on os
    set_pem_perms(&pem_path)?;
    // Security group
    // Todo: Should we have vpc_id?
    print!("Creating security group.. ");
    let security_group_id = match ec2_client
        .create_security_group(CreateSecurityGroupRequest {
            group_name: server_name.clone(),
            description: format!("For {}", server_name),
            dry_run: Some(dry_run),
            vpc_id: None,
        })
        .sync()
        .map_err(er::Rusoto::e)?
        .group_id
    {
        Some(group_id) => group_id,
        None => return er::err("Failed to get security group_id"),
    };
    println!("OK");
    // Add inbound http and https rules
    print!("Adding inbound rules.. ");
    ec2_client
        .authorize_security_group_ingress(AuthorizeSecurityGroupIngressRequest {
            group_id: Some(security_group_id.clone()),
            group_name: None,
            ip_permissions: Some(vec![
                // Ssh
                IpPermission {
                    from_port: Some(22),
                    to_port: Some(22),
                    ip_protocol: Some("tcp".to_string()),
                    ip_ranges: Some(vec![IpRange {
                        cidr_ip: Some("0.0.0.0/0".to_string()),
                        description: Some("Ssh traffic".to_string()),
                    }]),
                    ipv_6_ranges: None,
                    prefix_list_ids: None,
                    user_id_group_pairs: None,
                },
                // Http
                IpPermission {
                    from_port: Some(80),
                    to_port: Some(80),
                    ip_protocol: Some("tcp".to_string()),
                    ip_ranges: Some(vec![IpRange {
                        cidr_ip: Some("0.0.0.0/0".to_string()),
                        description: Some("Http traffic".to_string()),
                    }]),
                    ipv_6_ranges: None,
                    prefix_list_ids: None,
                    user_id_group_pairs: None,
                },
                // Https
                IpPermission {
                    from_port: Some(443),
                    to_port: Some(443),
                    ip_protocol: Some("tcp".to_string()),
                    ip_ranges: Some(vec![IpRange {
                        cidr_ip: Some("0.0.0.0/0".to_string()),
                        description: Some("Https traffic".to_string()),
                    }]),
                    ipv_6_ranges: None,
                    prefix_list_ids: None,
                    user_id_group_pairs: None,
                },
                // Video udp
                IpPermission {
                    from_port: Some(10_000),
                    to_port: Some(10_000),
                    ip_protocol: Some("udp".to_string()),
                    ip_ranges: Some(vec![IpRange {
                        cidr_ip: Some("0.0.0.0/0".to_string()),
                        description: Some("UDP video".to_string()),
                    }]),
                    ipv_6_ranges: None,
                    prefix_list_ids: None,
                    user_id_group_pairs: None,
                }
            ]),
            dry_run: Some(dry_run),
            from_port: None,
            to_port: None,
            cidr_ip: None,
            ip_protocol: None,
            source_security_group_name: None,
            source_security_group_owner_id: None,
        })
        .sync()
        .map_err(er::Rusoto::e)?;
    println!("OK");
    print!("Creating ec2 instance.. ");
    // Create and run ec2 instance
    let reservation = ec2_client
        .run_instances(RunInstancesRequest {
            image_id: Some("ami-3f36be41".to_string()),
            max_count: 1,
            min_count: 1,
            instance_type: Some("t3.micro".to_string()),
            key_name: Some(server_name.clone()),
            dry_run: Some(dry_run),
            block_device_mappings: None,
            additional_info: None,
            capacity_reservation_specification: None,
            client_token: None,
            cpu_options: None,
            credit_specification: None,
            disable_api_termination: None,
            ebs_optimized: None,
            elastic_gpu_specification: None,
            elastic_inference_accelerators: None,
            hibernation_options: None,
            iam_instance_profile: None,
            instance_initiated_shutdown_behavior: None,
            instance_market_options: None,
            ipv_6_address_count: None,
            ipv_6_addresses: None,
            kernel_id: None,
            launch_template: None,
            license_specifications: None,
            monitoring: None,
            network_interfaces: None,
            placement: None,
            private_ip_address: None,
            ramdisk_id: None,
            security_group_ids: Some(vec![security_group_id.clone()]),
            security_groups: None,
            subnet_id: None,
            tag_specifications: None,
            user_data: None,
        })
        .sync()
        .map_err(er::Rusoto::e)?;
    println!("OK");
    // Get the instance id
    let instance_id = match reservation.instances {
        Some(instances) => {
            if instances.len() != 1 {
                return er::err(format!(
                    "Number of instances unexpectedly not one, but: {}",
                    instances.len()
                ));
            }
            instances
                .into_iter()
                .next()
                .and_then(|i| i.instance_id)
                .ok_or(er::error("Could not get instance_id"))?
        }
        None => {
            return er::err("No instances reserved after request");
        }
    };
    println!("Ec2 instance launching!");
    // Save configuration
    let conf = crate::server::ServerConfig {
        name: server_name,
        pem: pem_file,
        url: format!("{}:22", addr.public_ip),
        instance_id: Some(instance_id),
        elastic_ip: Some(addr),
    };
    crate::server::write_config(env, &conf)?;
    // Could let machine boot up in background here,
    // and include this call as needed
    wait_for_running_and_finish(env, conf)
}

/// Waits for instance to be in running state, then
/// requests host token
pub fn wait_for_running_and_finish(env: &CliEnv, server_conf: server::ServerConfig) -> Result<()> {
    use rusoto_ec2::DescribeInstanceStatusRequest;
    let instance_id = match server_conf.instance_id {
        Some(instance_id) => instance_id,
        None => {
            eprintln!("No instance_id registered on the server");
            return er::err("No instance_id registered");
        }
    };
    // Could maybe accept ec2_client as arg, for
    // now I don't think it matters too much
    let ec2_client = create_ec2_client(&env)?;
    // 3 minute timeout waiting for the machine to run
    let timeout = std::time::Duration::from_secs(180);
    let initiated = std::time::Instant::now();
    while initiated.elapsed() < timeout {
        let describe_instance = ec2_client
            .describe_instance_status(DescribeInstanceStatusRequest {
                dry_run: None,
                instance_ids: Some(vec![instance_id.clone()]),
                // Include non-running instances
                include_all_instances: Some(true),
                filters: None,
                max_results: None,
                next_token: None,
            })
            .sync()
            .map_err(er::Rusoto::e)?;
        match describe_instance.instance_statuses {
            Some(statuses) => {
                if statuses.len() < 1 {
                    return er::err("0 instance statuses returned");
                }
                let instance_state = match statuses
                    .into_iter()
                    .find(|s| s.instance_id.as_ref() == Some(&instance_id))
                {
                    Some(status) => match status.instance_state.and_then(|s| s.name) {
                        Some(state_name) => state_name,
                        None => return er::err("No state name given"),
                    },
                    None => {
                        return er::err("Could not find status of instance");
                    }
                };
                match instance_state.as_str() {
                    "pending" => println!("Pending state"),
                    "running" => {
                        println!("Running!");
                        // Breaking loop
                        break;
                    }
                    "shutting-down" | "terminated" | "stopping" | "stopped" => {
                        eprintln!("Post-running state: {}, aborting", instance_state);
                        return er::err("Post running state");
                    }
                    _ => {
                        eprintln!("Unrecognized state: {}, aborting", instance_state);
                        return er::err("Unrecognized state");
                    }
                }
            }
            None => {
                eprintln!("Instance not found: {:?}", instance_id);
                return er::err("Instance not found");
            }
        }
        // Sleep before next iteration/check
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    // Associate address
    match server_conf.elastic_ip {
        Some(addr) => {
            println!("Associating address.. ");
            ec2_client
                .associate_address(AssociateAddressRequest {
                    instance_id: Some(instance_id.clone()),
                    allocation_id: Some(addr.allocation_id),
                    public_ip: None,
                    allow_reassociation: Some(false),
                    dry_run: None,
                    network_interface_id: None,
                    private_ip_address: None,
                })
                .sync()
                .map_err(er::Rusoto::e)?;
            println!("OK");
        }
        None => (),
    }
    // When running we can get the host fingerprint, so
    // we can verify host, with
    // https://docs.rs/rusoto_ec2/0.40.0/rusoto_ec2/trait.Ec2.html#tymethod.get_console_output
    // This I thought, but getting None out of these now
    use rusoto_ec2::GetConsoleOutputRequest;
    let x = ec2_client
        .get_console_output(GetConsoleOutputRequest {
            dry_run: None,
            instance_id: instance_id.clone(),
            latest: None,
        })
        .sync();
    println!("{:?}", x.unwrap().output);
    let x = ec2_client
        .get_console_output(GetConsoleOutputRequest {
            dry_run: None,
            instance_id: instance_id.clone(),
            latest: Some(true),
        })
        .sync();
    println!("{:?}", x.unwrap().output);
    Ok(())
}
