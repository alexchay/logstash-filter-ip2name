# encoding: utf-8

require 'spec_helper'
require "logstash/filters/ip2name"

YAMLFILE = File.join(File.dirname(__FILE__), "ip2name.yaml")

describe LogStash::Filters::IP2Name do

  describe "Resolve ip address to name" do
    let(:config) do <<-CONFIG
      filter {
        ip2name {
          address_field => "ip_address"
          yamlfile_path => "#{YAMLFILE}"
          name_field => "ip_name"
          fallback => "%{ip_address}"
        }
      }
    CONFIG
    end

    sample("ip_address" => "11.11.11.11") do
      expect(subject).to include('ip_name')
      expect(subject['ip_name']).to eq('example.io')
    end
    sample("ip_address" => "10.10.10.10") do
      expect(subject).to include('ip_name')
      expect(subject['ip_name']).to eq('example.local.10')
    end
    sample("ip_address" => "11.10.10.11") do
      expect(subject).to include('ip_name')
      expect(subject['ip_name']).to eq('11.10.10.11')
    end
  end
end
