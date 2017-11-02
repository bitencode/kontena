require 'openssl'
require 'acme-client'

require_relative '../../services/logging'

module GridCertificates
  module Common
    include Logging
    include WaitHelper

    LE_PRIVATE_KEY = 'LE_PRIVATE_KEY'.freeze

    ACME_ENDPOINT = 'https://acme-v01.api.letsencrypt.org/'.freeze

    def acme_client(grid)
      client = Acme::Client.new(private_key: acme_private_key(grid),
                                endpoint: acme_endpoint,
                                connection_options: { request: { open_timeout: 5, timeout: 5 } })
      client
    end

    def acme_private_key(grid)
      le_secret = grid.grid_secrets.where(name: LE_PRIVATE_KEY).first
      if le_secret.nil?
        info 'LE private key does not yet exist, creating...'
        private_key = OpenSSL::PKey::RSA.new(4096)
        outcome = GridSecrets::Create.run(grid: grid, name: LE_PRIVATE_KEY, value: private_key.to_pem)
        unless outcome.success?
          return nil # TODO Or raise something?
        end
      else
        private_key = OpenSSL::PKey::RSA.new(le_secret.value)
      end

      private_key
    end

    def domain_to_vault_key(domain)
      domain.sub('.', '_')
    end

    def acme_endpoint
      ENV['ACME_ENDPOINT'] || ACME_ENDPOINT
    end

    def resolve_service(grid, service_name)
      stack_name, service = service_name.split('/')
      stack = grid.stacks.find_by(name: stack_name)
      return nil if stack.nil?

      stack.grid_services.find_by(name: service)
    end

    # @param grid [Grid]
    # @param domain [String]
    # @return [GridDomainAuthorization, nil]
    def get_authz_for_domain(grid, domain)
      grid.grid_domain_authorizations.find_by(domain: domain)
    end

    # @param domain [String]
    # @param expected_record [String] TXT record content
    def check_dns_record(domain, expected_record)
      resolv = Resolv::DNS.new()
      info "validating domain:_acme-challenge.#{domain}"
      resource = resolv.getresource("_acme-challenge.#{domain}", Resolv::DNS::Resource::IN::TXT)
      info "got record: #{resource.strings}, expected: #{expected_record}"
      expected_record == resource.strings[0]
    rescue
      false
    end

    # @param domain_authorization [GridDomainAuthorization]
    def validate_domain_authorization(authz)

      case authz.authorization_type
      when 'dns-01'
        # Check that the expected DNS record is already in place
        unless check_dns_record(authz.domain, authz.challenge_opts['record_content'])
          add_error(:dns_record, :invalid, "Expected DNS record not present for domain #{authz.domain}") # XXX: validations error type
        end
      end
    end

    # @param domains [Array<String>]
    def validate_authorizations_for_domains(domains)
      domains.each do |domain|
        unless domain_authorization = get_authz_for_domain(self.grid, domain)
          add_error(:authorization, :not_found, "Domain authorization not found for domain #{domain}") # XXX: validations error type
          return # No point to continue validations
        end

        validate_domain_authorization(domain_authorization)
      end
    end

    # @param grid [Grid]
    # @param le_client [Acme::Client] for grid
    # @param domain [String]
    # @raise [Timeout::Error]
    def verify_domain(grid, le_client, domain)
      domain_authorization = get_authz_for_domain(grid, domain)
      challenge = le_client.challenge_from_hash(domain_authorization.challenge)
      if domain_authorization.state == :created
        info "requesting verification for domain #{domain}"
        success = challenge.request_verification
        if success
          domain_authorization.state = :requested
          domain_authorization.save
        else
          add_error(:request_verification, :failed, "Requesting verification failed")
        end
      end

      wait_until!("domain verification for #{domain} is valid", interval: 1, timeout: 30, threshold: 10) {
        challenge.verify_status != 'pending'
      }

      case challenge.verify_status
      when 'valid'
        domain_authorization.expires = nil # XXX: old version of acme-client does not update authorization expiration
        domain_authorization.state = :validated
      when 'invalid'
        domain_authorization.state = :invalid
        add_error(:challenge, :invalid, challenge.error['detail'])
      end

      domain_authorization.save
    rescue Timeout::Error
      warn 'timeout while waiting for DNS verfication status'
      add_error(:challenge_verify, :timeout, 'Challenge verification timeout')
    rescue Acme::Client::Error => exc
      error exc
      add_error(:acme_client, :error, exc.message)
    end

    # @param grid [Grid]
    # @param le_client [Acme::Client] for grid
    # @param domains [Array<String>]
    # @raise [Timeout::Error]
    # @return [Boolean] success/error
    def verify_domains(grid, le_client, domains)
      domains.each do |domain|
        verify_domain(grid, le_client, domain)
      end

      # some domain verifications has failed, errors already added
      return !has_errors?
    end
  end
end
