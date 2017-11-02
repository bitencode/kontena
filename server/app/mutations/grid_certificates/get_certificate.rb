require 'timeout'

require_relative 'common'
require_relative '../../services/logging'

# DEPRECATED
#
# This mutation deals with the "legacy" mode of operation and stores certs as secrets.
# As the old API will still be around for some time so will this mutation.
#
module GridCertificates
  class GetCertificate < Mutations::Command
    include Common
    include Logging
    include WaitHelper

    LE_CERT_PREFIX = 'LE_CERTIFICATE'.freeze

    required do
      model :grid, class: Grid
      string :secret_name

      array :domains do
        string
      end
      string :cert_type, in: ['cert', 'chain', 'fullchain'], default: 'fullchain'
    end

    def validate
      validate_authorizations_for_domains(self.domains)
    end

    def execute

      csr = Acme::Client::CertificateRequest.new(names: self.domains)
      client = acme_client(self.grid)

      return unless verify_domains(self.grid, client, self.domains)

      certificate = client.new_certificate(csr)
      cert_priv_key = certificate.request.private_key.to_pem
      cert = nil
      case self.cert_type
        when 'fullchain'
          cert = certificate.fullchain_to_pem
        when 'chain'
          cert = certificate.chain_to_pem
        when 'cert'
          cert = certificate.to_pem
      end


      secrets = []
      secrets << upsert_secret("#{self.secret_name}_PRIVATE_KEY", cert_priv_key)
      secrets << upsert_secret("#{self.secret_name}_CERTIFICATE", cert)
      secrets << upsert_secret("#{self.secret_name}_BUNDLE", [cert, cert_priv_key].join)

      secrets
    rescue Timeout::Error
      warn 'timeout while waiting for DNS verfication status'
      add_error(:challenge_verify, :timeout, 'Challenge verification timeout')
    rescue Acme::Client::Error => exc
      error "#{exc.class.name}: #{exc.message}"
      error exc.backtrace.join("\n") if exc.backtrace
      add_error(:acme_client, :error, exc.message)
    end

    def upsert_secret(name, value)
      cert_secret = self.grid.grid_secrets.find_by(name: name)
      if cert_secret
        outcome = GridSecrets::Update.run(grid_secret: cert_secret, value: value)
      else
        outcome = GridSecrets::Create.run(grid: self.grid, name: name, value: value)
      end

      unless outcome.success?
        add_error(:cert_store, :failure, "Certificate storing to vault failed: #{outcome.errors.message}")
        return
      end
      outcome.result
    end
  end
end
