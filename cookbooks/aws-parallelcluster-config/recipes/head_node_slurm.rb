# frozen_string_literal: true

#
# Cookbook Name:: aws-parallelcluster
# Recipe:: head_node_slurm_config
#
# Copyright 2013-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the
# License. A copy of the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "LICENSE.txt" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions and
# limitations under the License.

setup_munge_head_node

# Export /opt/slurm
nfs_export "/opt/slurm" do
  network node['cluster']['ec2-metadata']['vpc-ipv4-cidr-blocks']
  writeable true
  options ['no_root_squash']
end

# Ensure config directory is in place
directory '/opt/slurm/etc' do
  user 'root'
  group 'root'
  mode '0755'
end

# Create directory configured as StateSaveLocation
directory '/var/spool/slurm.state' do
  user node['cluster']['slurm']['user']
  group node['cluster']['slurm']['group']
  mode '0700'
end

template '/opt/slurm/etc/slurm.conf' do
  source 'slurm/slurm.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

template '/opt/slurm/etc/gres.conf' do
  source 'slurm/gres.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

# Copy pcluster config generator and templates
remote_directory "#{node['cluster']['scripts_dir']}/slurm" do
  source 'head_node_slurm/slurm'
  mode '0755'
  action :create
  recursive true
end

unless virtualized?
  # Copy cluster config file from S3 URI
  fetch_config_command = "#{node['cluster']['cookbook_virtualenv_path']}/bin/aws s3api get-object"\
                         " --bucket #{node['cluster']['cluster_s3_bucket']}"\
                         " --key #{node['cluster']['cluster_config_s3_key']}"\
                         " --region #{node['cluster']['region']} #{node['cluster']['cluster_config_path']}"
  fetch_config_command += " --version-id #{node['cluster']['cluster_config_version']}" unless node['cluster']['cluster_config_version'].nil?
  execute "copy_cluster_config_from_s3" do
    command fetch_config_command
    retries 3
    retry_delay 5
  end

  # Copy instance type infos file from S3 URI
  fetch_config_command = "#{node['cluster']['cookbook_virtualenv_path']}/bin/aws s3api get-object --bucket #{node['cluster']['cluster_s3_bucket']}"\
                         " --key #{node['cluster']['instance_types_data_s3_key']} --region #{node['cluster']['region']} #{node['cluster']['instance_types_data_path']}"
  execute "copy_instance_type_data_from_s3" do
    command fetch_config_command
    retries 3
    retry_delay 5
  end

  execute 'initialize compute fleet status in DynamoDB' do
    # Initialize the status of the compute fleet in the DynamoDB table. Set it to RUNNING.
    command "#{node['cluster']['cookbook_virtualenv_path']}/bin/aws dynamodb put-item --table-name #{node['cluster']['ddb_table']}"\
            " --item '{\"Id\": {\"S\": \"COMPUTE_FLEET\"}, \"Status\": {\"S\": \"RUNNING\"}, \"LastUpdatedTime\": {\"S\": \"#{Time.now.utc}\"}}'"\
            " --region #{node['cluster']['region']}"
    retries 3
    retry_delay 5
  end

  # Generate pcluster specific configs
  no_gpu = nvidia_installed? ? "" : "--no-gpu"
  execute "generate_pcluster_slurm_configs" do
    command "#{node['cluster']['cookbook_virtualenv_path']}/bin/python #{node['cluster']['scripts_dir']}/slurm/pcluster_slurm_config_generator.py"\
            " --output-directory /opt/slurm/etc/ --template-directory #{node['cluster']['scripts_dir']}/slurm/templates/"\
            " --input-file #{node['cluster']['cluster_config_path']}  --instance-types-data #{node['cluster']['instance_types_data_path']} #{no_gpu}"
  end
end

# all other OSs use /sys/fs/cgroup, which is the default
template '/opt/slurm/etc/cgroup.conf' do
  source 'slurm/cgroup.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

cookbook_file '/opt/slurm/etc/slurm.sh' do
  source 'head_node_slurm/slurm.sh'
  owner 'root'
  group 'root'
  mode '0755'
end

cookbook_file '/opt/slurm/etc/slurm.csh' do
  source 'head_node_slurm/slurm.csh'
  owner 'root'
  group 'root'
  mode '0755'
end

template "#{node['cluster']['scripts_dir']}/slurm/slurm_resume" do
  source 'slurm/resume_program.erb'
  owner node['cluster']['slurm']['user']
  group node['cluster']['slurm']['group']
  mode '0744'
end

file "/var/log/parallelcluster/slurm_resume.log" do
  owner node['cluster']['cluster_admin_user']
  group node['cluster']['cluster_admin_group']
  mode '0644'
end

template "#{node['cluster']['slurm_plugin_dir']}/parallelcluster_slurm_resume.conf" do
  source 'slurm/parallelcluster_slurm_resume.conf.erb'
  owner node['cluster']['cluster_admin_user']
  group node['cluster']['cluster_admin_group']
  mode '0644'
end

template "#{node['cluster']['scripts_dir']}/slurm/slurm_suspend" do
  source 'slurm/suspend_program.erb'
  owner node['cluster']['slurm']['user']
  group node['cluster']['slurm']['group']
  mode '0744'
end

file "/var/log/parallelcluster/slurm_suspend.log" do
  owner node['cluster']['cluster_admin_user']
  group node['cluster']['cluster_admin_group']
  mode '0644'
end

template "#{node['cluster']['slurm_plugin_dir']}/parallelcluster_slurm_suspend.conf" do
  source 'slurm/parallelcluster_slurm_suspend.conf.erb'
  owner node['cluster']['cluster_admin_user']
  group node['cluster']['cluster_admin_group']
  mode '0644'
end

template "#{node['cluster']['slurm_plugin_dir']}/parallelcluster_clustermgtd.conf" do
  source 'slurm/parallelcluster_clustermgtd.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

# Create shared directory used to store clustermgtd heartbeat and computemgtd config
directory "/opt/slurm/etc/pcluster/.slurm_plugin" do
  user node['cluster']['cluster_admin_user']
  group node['cluster']['cluster_admin_group']
  mode '0755'
  action :create
  recursive true
end

# Put computemgtd config under /opt/slurm/etc/pcluster/.slurm_plugin so all compute nodes share a config
template "/opt/slurm/etc/pcluster/.slurm_plugin/parallelcluster_computemgtd.conf" do
  source 'slurm/parallelcluster_computemgtd.conf.erb'
  owner 'root'
  group 'root'
  mode '0644'
end

cookbook_file '/etc/systemd/system/slurmctld.service' do
  source 'head_node_slurm/slurmctld.service'
  owner 'root'
  group 'root'
  mode '0644'
  action :create
end

service "slurmctld" do
  supports restart: false
  action %i[enable start]
end
