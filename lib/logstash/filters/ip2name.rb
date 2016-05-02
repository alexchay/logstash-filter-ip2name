# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "yaml"
require "ipaddr"


# A general search and replace tool which uses a YAML file to determine
# replacement values.
# An external YAML file (readable by logstash) must be specified
# in the `file_path` configuration item.
#
# YAML file contains CIDR ranges and corresponding them names and should like this:
#  ---
# Each range is defined like so
# 11.11.11.11     : "example.io"
# 10.10.10.0/24   : "example.local"
# ....
#
# if ip address in the event field specified in the `address_field` configuration
# falls inside a given CIDR range, the field's value will be substituted
# with the matched key's value (in our case it's name of range) from the dictionary.

class LogStash::Filters::IP2Name < LogStash::Filters::Base
  config_name "ip2name"

  # The name of the logstash event field containing the value to be checked against
  # a list of networks blocks that might contain it.
  config :address_field, :validate => :string, :required => true

  # The full path of the external YAML dictionary file.
  config :yamlfile_path, :validate => :path

  # This setting indicates how frequently
  # (in seconds) logstash will check the YAML file for updates.
  config :refresh_interval, :validate => :number, :default => 300

  # The destination field you wish to populate with the matched name.
  # Set this to the same value as source if you want to do a substitution,
  # in this case filter will allways succeed. This will clobber
  # the old value of the source field!
  config :name_field, :validate => :string, :default => "ip2name"

  # This configuration can be dynamic and include parts of the event using the `%{field}` syntax.
  config :fallback, :validate => :string

  public
  def register
    @ip2name  = Hash.new
    @prefixes = Hash.new
    @next_refresh = Time.now + @refresh_interval
    load_yaml_file
  end # def register

  public
  def load_yaml_file
    if @yamlfile_path
      begin
        @ip2name.merge!(YAML.load_file(@yamlfile_path)) if File.exists?(@yamlfile_path)
        prefixes = {}
        @ip2name.keys.each do |key|
          prefix = key[/(\d+\.){3}(\d+){1}\/(\d+)/,3].to_i
          prefixes[prefix] = prefixes[prefix].to_i + 1
        end
        @prefixes = prefixes.keys.sort_by { |key| prefixes[key] }.reverse.select { |prefix| prefix.between?(1,30) }
      rescue => e
        @logger.error("Exception in #{self.class.name}: Bad syntax in YAML file #{@yamlfile_path}", "exception" => e, "backtrace" => e.backtrace)
      end
    end
  end

  public
  def filter(event)
    return unless filter?(event)

    if @next_refresh < Time.now
      logger.debug("Refreshing dictionary file into a cache")
      load_yaml_file
      @next_refresh = Time.now + @refresh_interval
    end

    return unless event.include?(@address_field) # Skip translation in case event does not have @address_field field.

    begin
      matched = false
      ip = event[@address_field].to_s
      # if ip address has a specified hostname
      name = @ip2name[ip]
      # otherwise check a given ip address falls inside a CIDR range.
      if not name
        ipaddr = IPAddr.new(ip)
        @prefixes.each do |prefix|
          name = @ip2name[ipaddr.mask(prefix).to_s + '/' + prefix.to_s]
          if name then
            ip_a = ip.split('.')
            (prefix/8).upto(3) {|i| name += '.' + ip_a[i]}
            break
          end
        end
      end

      if name
        event[@name_field] = name
        matched = true
      elsif @fallback
        event[@name_field] = event.sprintf(@fallback)
        matched = true
      end

      filter_matched(event) if matched
    rescue => e
      @logger.error("Something went wrong when attempting to resolve ip address to name", :exception => e, :field => @address_field, :event => event)
    end
  end # def filter
end # class LogStash::Filters::Example
