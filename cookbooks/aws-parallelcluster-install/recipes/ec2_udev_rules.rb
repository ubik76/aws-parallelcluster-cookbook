# frozen_string_literal: true

#
# Cookbook Name:: aws-parallelcluster
# Recipe:: ec2_udev_rules
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

template 'ec2-volid.rules' do
  source 'ec2_udev_rules/ec2-volid.rules.erb'
  path '/etc/udev/rules.d/52-ec2-volid.rules'
  user 'root'
  group 'root'
  mode '0644'
end

template 'parallelcluster-ebsnvme-id' do
  source 'ec2_udev_rules/parallelcluster-ebsnvme-id.erb'
  path '/usr/local/sbin/parallelcluster-ebsnvme-id'
  user 'root'
  group 'root'
  mode '0744'
end

cookbook_file 'ec2_dev_2_volid.py' do
  source 'ec2_udev_rules/ec2_dev_2_volid.py'
  path '/sbin/ec2_dev_2_volid.py'
  user 'root'
  group 'root'
  mode '0744'
end

cookbook_file 'ec2blkdev-init' do
  source 'ec2_udev_rules/ec2blkdev-init'
  path '/etc/init.d/ec2blkdev'
  user 'root'
  group 'root'
  mode '0744'
end

cookbook_file 'attachVolume.py' do
  source 'ec2_udev_rules/attachVolume.py'
  path '/usr/local/sbin/attachVolume.py'
  user 'root'
  group 'root'
  mode '0755'
end

if node['platform'] == 'ubuntu'
  # allow Ubuntu udev to do network call
  execute 'udev-daemon-reload' do
    command 'udevadm control --reload'
    action :nothing
  end

  directory '/etc/systemd/system/systemd-udevd.service.d'

  # Disable udev network sandbox and notify udev to reload configuration
  cookbook_file 'udev-override.conf' do
    source 'ec2_udev_rules/udev-override.conf'
    path '/etc/systemd/system/systemd-udevd.service.d/override.conf'
    user 'root'
    group 'root'
    mode '0644'
    notifies :run, "execute[udev-daemon-reload]", :immediately
  end
end

service "ec2blkdev" do
  supports restart: true
  action %i[enable start]
end
