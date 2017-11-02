require 'timeout'

require_relative 'common'
require_relative '../../services/logging'

module GridCertificates
  class RequestCertificate < Mutations::Command
    include Common
    include Logging

    required do
      model :grid, class: Grid
      array :domains do
        string
      end
    end

    def validate
      validate_authorizations_for_domains(self.domains)
    end

    def has_errors?
      return true if @errors && @errors.size > 0
      false
    end

    def execute
      return unless verify_domains(self.grid, self.le_client, self.domains)

      csr = Acme::Client::CertificateRequest.new(names: self.domains)
      certificate = le_client.new_certificate(csr)

      certificate_model = self.grid.certificates.find_by(subject: self.domains[0])

      if certificate_model
        certificate_model.alt_names = self.domains[1..-1]
        certificate_model.valid_until = certificate.x509.not_after
        certificate_model.private_key = certificate.request.private_key.to_pem
        certificate_model.certificate = certificate.to_pem
        certificate_model.chain = certificate.chain_to_pem

        certificate_model.save
      else
        certificate_model = Certificate.create!(
          grid: self.grid,
          subject: self.domains[0],
          alt_names: self.domains[1..-1],
          valid_until: certificate.x509.not_after,
          private_key: certificate.request.private_key.to_pem,
          certificate: certificate.to_pem,
          chain: certificate.chain_to_pem
        )
      end

      refresh_grid_services(certificate_model)

      certificate_model

    rescue Acme::Client::Error => exc
      error exc
      add_error(:acme_client, :error, exc.message)
    end

    def le_client
      @le_client ||= acme_client(self.grid)
    end

    ##
    # @param [Certificate]
    def refresh_grid_services(certificate)
      certificate.grid.grid_services.where(:'certificates.subject' => certificate.subject).each do |grid_service|
        info "force service #{grid_service.to_path} update for updated certificate #{certificate.subject}"
        grid_service.set(updated_at: Time.now.utc)
      end
    end
  end

end
