# frozen_string_literal: true

require 'resolv'
require 'socket'
require 'uri'
require 'timeout'

module Dmarcaudit
  module DnsRecordFetcher
    DEFAULT_TIMEOUT = 5 # seconds per query
    MAX_RETRIES = 3
    RETRY_DELAY = 0.1 # seconds between retries
    DEFAULT_DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '208.67.222.222']

    class DnsError < StandardError; end

    class TimeoutError < DnsError; end

    class RecordNotFound < DnsError; end

    # Represents a parsed DNS record
    class ParsedRecord
      attr_reader :type, :name, :ttl, :content, :class

      def initialize(type:, name:, ttl: 300, content: '', class: 'IN')
        @type = type
        @name = name
        @ttl = ttl
        @content = content
        @class = class
      end

      def to_h
        { type: type, name: name, ttl: ttl, content: content, class: class }
      end

      def inspect
        "#<ParsedRecord #{type} #{name.inspect}> (#{content.inspect})"
      end
    end

    # Main DNS fetcher with retry logic and multiple server support
    class Client
      attr_reader :dns_servers, :default_timeout

      def initialize(dns_servers: DEFAULT_DNS_SERVERS, default_timeout: DEFAULT_TIMEOUT)
        @dns_servers = dns_servers
        @default_timeout = default_timeout
      end

      # Fetch a single record with retry and fallback logic
      def fetch(type:, name:, class: 'IN', timeout: nil)
        query_name = normalize_name(name)
        query_type = type.to_s.upcase
        query_class = class.to_s.upcase

        timeout ||= @default_timeout

        # Try each DNS server in order
        dns_servers.each do |server|
          result = attempt_query(server, query_name, query_type, query_class, timeout)
          return result if result
        end

        raise RecordNotFound, "Record not found after trying all servers: #{query_name} (#{query_type})"
      rescue TimeoutError => e
        raise TimeoutError, "Timeout fetching from all servers: #{e.message}"
      end

      # Fetch multiple records in parallel where possible
      def fetch_batch(types:, name:, class: 'IN', timeout: nil)
        results = {}

        types.each do |type|
          begin
            results[type] = fetch(type: type, name: name, class: class, timeout: timeout)
          rescue RecordNotFound => e
            results[type] = ParsedRecord.new(
              type: type,
              name: name,
              content: "#<#{e.class}: #{e.message}>"
            )
          end
        end

        results
      end

      # Fetch MX records (used for DMARC verification)
      def fetch_mx(name:, timeout: nil)
        fetch(type: 'MX', name: name, timeout: timeout).content.split("\n").map do |line|
          parts = line.strip.split
          raise RecordNotFound, "Malformed MX record: #{line}" if parts.size < 2

          { priority: parts[0].to_i, exchange: parts[1] }
        end.compact
      rescue RecordNotFound => e
        []
      end

      # Fetch TXT records (SPF, DMARC, DKIM)
      def fetch_txt(name:, timeout: nil)
        record = fetch(type: 'TXT', name: name, timeout: timeout)
        return [] if record.content.nil? || record.content.empty?

        record.content.split.map do |line|
          line.strip.presence || ''
        end.compact
      rescue RecordNotFound => e
        []
      end

      # Fetch AAAA records (IPv6)
      def fetch_aaaa(name:, timeout: nil)
        fetch(type: 'AAAA', name: name, timeout: timeout).content.split("\n").map do |ip|
          ip.strip.presence || ''
        end.compact
      rescue RecordNotFound => e
        []
      end

      # Fetch A records (IPv4)
      def fetch_a(name:, timeout: nil)
        fetch(type: 'A', name: name, timeout: timeout).content.split("\n").map do |ip|
          ip.strip.presence || ''
        end.compact
      rescue RecordNotFound => e
        []
      end

      # Fetch CNAME records
      def fetch_cname(name:, timeout: nil)
        fetch(type: 'CNAME', name: name, timeout: timeout).content.split("\n").map do |target|
          target.strip.presence || ''
        end.compact
      rescue RecordNotFound => e
        []
      end

      # Fetch SRV records (used for some DMARC configurations)
      def fetch_srv(name:, timeout: nil)
        fetch(type: 'SRV', name: name, timeout: timeout).content.split("\n").map do |line|
          parts = line.strip.split
          raise RecordNotFound, "Malformed SRV record: #{line}" if parts.size < 5

          {
            priority: parts[0].to_i,
            weight: parts[1].to_i,
            port: parts[2].to_i,
            target: parts[3]
          }
        end.compact
      rescue RecordNotFound => e
        []
      end

      # Fetch all records for a domain (useful for debugging)
      def fetch_all(name:, timeout: nil)
        {
          A: fetch_a(name: name, timeout: timeout),
          AAAA: fetch_aaaa(name: name, timeout: timeout),
          MX: fetch_mx(name: name, timeout: timeout),
          TXT: fetch_txt(name: name, timeout: timeout),
          CNAME: fetch_cname(name: name, timeout: timeout)
        }
      end

    private

      # Normalize the DNS query name (remove trailing dots, handle wildcards)
      def normalize_name(name)
        return name if name.nil? || name.empty?

        normalized = name.to_s.strip
        normalized = normalized.sub(/\.$/, '') unless normalized.end_with?('.')

        normalized
      end

      # Attempt a single DNS query with timeout and retry
      def attempt_query(server, name, type, class_, timeout)
        resolver = Resolv::DNS.new([server])
        begin
          result = resolver.getresources(name, type, class_)
          return parse_result(result, type, name) if result.any?

          # Check for NOERROR with empty answer (record exists but no data)
          response_code = resolver.last_response.code
          if response_code == 0 || response_code == Resolv::DNS::RCode::NOERROR
            return ParsedRecord.new(type: type, name: name, content: '')
          end

          # Check for NXDOMAIN
          if response_code == Resolv::DNS::RCode::NXDOMAIN
            raise RecordNotFound, "NXDOMAIN: #{name}"
          end

        rescue ResolvTimeoutError => e
          raise TimeoutError, "Query to #{server} timed out"
        rescue ResolvError => e
          raise DnsError, "Query error from #{server}: #{e.message}"
        end

        nil
      end

      # Parse the DNS response into a ParsedRecord
      def parse_result(resources, type, name)
        content_parts = resources.map do |rr|
          rr.to_s.split(' ').first(4).join(' ')
        end.join("\n")

        ParsedRecord.new(type: type, name: name, content: content_parts)
      rescue ResolvError => e
        raise DnsError, "Failed to parse DNS response: #{e.message}"
      end
    end

    # Convenience module methods that work with the default client
    module ClassMethods
      def fetch(type:, name:, class: 'IN', timeout: nil)
        Client.new.fetch(type: type, name: name, class: class, timeout: timeout)
      end

      def fetch_mx(name:, timeout: nil)
        Client.new.fetch_mx(name: name, timeout: timeout)
      end

      def fetch_txt(name:, timeout: nil)
        Client.new.fetch_txt(name: name, timeout: timeout)
      end

      def fetch_aaaa(name:, timeout: nil)
        Client.new.fetch_aaaa(name: name, timeout: timeout)
      end

      def fetch_a(name:, timeout: nil)
        Client.new.fetch_a(name: name, timeout: timeout)
      end

      def fetch_all(name:, timeout: nil)
        Client.new.fetch_all(name: name, timeout: timeout)
      end
    end

    # Extend the module with class methods for convenience
    include ClassMethods
  end
end